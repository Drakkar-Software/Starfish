"""Request handling helpers for sync routes."""


import bisect
import ipaddress
import json
import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

from fastapi.responses import JSONResponse

from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.protocol.push import Author
from starfish_server.protocol.types import PushSuccess
from starfish_server.constants import QUERY_CHECKPOINT, ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON, APPEND_DEFAULT_FIELD

logger = logging.getLogger(__name__)

SAFE_PARAM = re.compile(r"^[a-zA-Z0-9._:@-]+$")
UNSAFE_KEY = re.compile(r"\.\.|[\x00-\x1f]|//")

UNSAFE_KEYS = frozenset({"__proto__", "constructor", "prototype"})

# Reject documents nested deeper than this. A deeply-nested body would otherwise
# overflow the recursive ``deep_sanitize`` (and, in CPython, ``json.loads`` itself),
# turning a tiny payload into an unhandled ``RecursionError`` → HTTP 500. Real
# Starfish documents are shallow (a keyring with epochs is ~5 deep), so 64 is far
# above any legitimate use while still well under the interpreter's recursion limit.
MAX_DOC_DEPTH = 64


def json_depth_within(obj: Any, limit: int = MAX_DOC_DEPTH) -> bool:
    """Return ``True`` iff *obj*'s nesting depth is within *limit*.

    Walks dicts and lists iteratively (an explicit stack, never the call stack) so
    the check itself cannot recurse. The push path runs this on the parsed body and
    rejects anything deeper than ``limit`` with HTTP 400 before sanitizing/storing.
    """
    stack = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return False
        children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return True


def _parse_host_ip(hostname: str) -> "ipaddress._BaseAddress | None":
    """Parse *hostname* to an IP address, canonicalising alternate IPv4
    notations the way an HTTP client would.

    ``ipaddress.ip_address`` only accepts canonical dotted-quad / IPv6, so
    ``2130706433`` (decimal), ``0x7f000001`` (hex), ``0177.0.0.1`` (octal), and
    ``127.1`` (short) — all of which resolve to ``127.0.0.1`` in common clients —
    would otherwise slip past the loopback check. ``socket.inet_aton`` applies
    the historical ``inet_addr`` rules and canonicalises them; genuine domain
    names raise ``OSError`` and return ``None`` (treated as public)."""
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass
    try:
        return ipaddress.ip_address(socket.inet_aton(hostname))
    except (OSError, ValueError):
        return None


def validate_url_not_private(url: str) -> bool:
    """Return True if the URL does not point to a private/internal network."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False
        addr = _parse_host_ip(hostname)
        if addr is not None and (
            addr.is_private or addr.is_loopback or addr.is_link_local
        ):
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


def validate_path_segment(value: str) -> bool:
    # fullmatch (not match): Python's `$` also matches *before* a trailing
    # newline, so SAFE_PARAM.match("alice\n") would wrongly pass. fullmatch
    # anchors both ends and rejects it, matching JS `$` (no /m) in the TS twin.
    return bool(SAFE_PARAM.fullmatch(value))


def is_unsafe_document_key(document_key: str) -> bool:
    """True when a resolved storage key contains a path-traversal or injection
    sequence (``..``, control chars, or ``//``). The single guard every
    read/write path must apply to its resolved ``document_key`` before touching
    the store — ``validate_path_segment`` only constrains one param's charset
    (it admits ``..``), so this is what actually blocks traversal in the
    composed key.
    """
    return bool(UNSAFE_KEY.search(document_key))


def deep_sanitize(obj: dict[str, Any]) -> dict[str, Any]:
    """Remove unsafe keys from a nested dict."""
    safe: dict[str, Any] = {}
    for key, val in obj.items():
        if key in UNSAFE_KEYS:
            continue
        if isinstance(val, dict):
            safe[key] = deep_sanitize(val)
        else:
            safe[key] = val
    return safe


def is_with_keyring_enabled(raw: str | None) -> bool:
    """Return True when the ``?withKeyring=`` query value should activate
    the sibling-keyring fetch. Accepts ``"1"`` and ``"true"`` (case-insensitive);
    any other value (including missing) is treated as off.
    """
    if raw is None:
        return False
    return raw.lower() in ("1", "true")


async def handle_sync_pull(
    document_key: str,
    store: AbstractObjectStore,
    checkpoint_param: str | None = None,
    force_full_fetch: bool = False,
    client_encrypted: bool = False,
    cache_duration_ms: int | None = None,
    is_public: bool = True,
    context: StoreContext | None = None,
    with_keyring: bool = False,
) -> JSONResponse:
    if is_unsafe_document_key(document_key):
        return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

    # Regular collections always return the full document. ``?checkpoint=`` is
    # ignored here (incremental sync is an appendOnly-only feature now); a stale
    # checkpoint param from an older client is harmless — we do NOT 400 on it.
    # ``force_full_fetch`` / ``client_encrypted`` are retained as inert no-ops
    # for call-site compatibility.
    result = await pull(store, document_key, context)
    body: dict[str, Any] = {
        "data": result.data,
        "hash": result.hash,
        "timestamp": result.timestamp,
    }
    if result.author_pubkey:
        body["authorPubkey"] = result.author_pubkey
    if result.author_signature:
        body["authorSignature"] = result.author_signature

    # ``?withKeyring=1`` optimization: piggyback the collection's sibling
    # keyring document at ``<document_key>/_keyring`` onto the pull response,
    # saving a round-trip on cold start. The keyring projection drops author
    # fields — the keyring document is unsigned in this model.
    #
    # NOTE: the sibling keyring read is authorized by the route layer, not here.
    # The pull handler only sets ``with_keyring=True`` after checking
    # ``<document_key>/_keyring`` against the caller's cap scope, so a cap that
    # denies the keyring (e.g. ``scopes.writer(col)``) never reaches this read.
    # This function only performs the storage read.
    if with_keyring:
        keyring_key = f"{document_key}/_keyring"
        # Treat ANY store error as "no keyring" (e.g. a filesystem store raising
        # NotADirectoryError when the data path is a leaf file and the app keeps its
        # keyring in a separate namespace). The optimization must degrade gracefully,
        # never crash the pull (HTTP 500).
        try:
            keyring_raw = await store.get_string(keyring_key, context=context)
        except Exception as exc:  # noqa: BLE001 — defensive: any store failure ⇒ no keyring
            logger.warning("withKeyring read failed for %r: %s", keyring_key, exc)
            keyring_raw = None
        if not keyring_raw:
            body["keyring"] = None
        else:
            try:
                parsed_kr = json.loads(keyring_raw)
                body["keyring"] = {
                    "data": parsed_kr.get("data", {}),
                    "hash": parsed_kr.get("hash", ""),
                    "timestamp": result.timestamp,
                }
            except (json.JSONDecodeError, ValueError) as exc:
                logger.error(
                    "Corrupt keyring document at key %r: %s", keyring_key, exc
                )
                body["keyring"] = None

    headers: dict[str, str] = {}
    if cache_duration_ms is not None:
        max_age = cache_duration_ms // 1000
        directive = f"max-age={max_age}" if is_public else f"private, max-age={max_age}"
        headers["Cache-Control"] = directive

    # ETag support
    doc_hash = result.hash
    if doc_hash:
        headers["ETag"] = f'"{doc_hash}"'

    return JSONResponse(body, headers=headers if headers else None)


async def handle_append_only_pull(
    document_key: str,
    store: AbstractObjectStore,
    checkpoint_param: str | None = None,
    append_field: str = APPEND_DEFAULT_FIELD,
    cache_duration_ms: int | None = None,
    is_public: bool = True,
    last_param: str | None = None,
    context: StoreContext | None = None,
) -> JSONResponse:
    """Pull handler for appendOnly persist=true collections.

    Each stored element is a ``{ts, data}`` envelope. When a checkpoint is
    requested, returns only elements whose ``ts`` is strictly greater than the
    checkpoint, found by binary search (the array is strictly increasing in
    ``ts``). ``?last=K`` then trims to the last K. The full ``{ts, data}``
    envelopes are returned — ``data`` is plaintext under "none" and an encryptor
    wrapper under "delegated".
    """
    if is_unsafe_document_key(document_key):
        return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

    checkpoint = 0
    if checkpoint_param is not None:
        try:
            parsed = int(checkpoint_param)
        except ValueError:
            return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
        if parsed < 0 or str(parsed) != checkpoint_param:
            return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
        checkpoint = parsed

    last: int | None = None
    if last_param is not None:
        try:
            parsed_last = int(last_param)
        except ValueError:
            return JSONResponse({"error": "Invalid last"}, status_code=400)
        if parsed_last < 0 or str(parsed_last) != last_param:
            return JSONResponse({"error": "Invalid last"}, status_code=400)
        last = parsed_last

    now = int(time.time() * 1000)
    raw = await store.get_string(document_key, context=context)

    if not raw:
        body: dict = {"data": {append_field: []}, "hash": "", "timestamp": now}
        headers: dict[str, str] = {}
        if cache_duration_ms is not None:
            max_age = cache_duration_ms // 1000
            directive = f"max-age={max_age}" if is_public else f"private, max-age={max_age}"
            headers["Cache-Control"] = directive
        return JSONResponse(body, headers=headers if headers else None)

    try:
        stored = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("Corrupt stored document at key %r during pull: %s", document_key, exc)
        body = {"data": {append_field: []}, "hash": "", "timestamp": now}
        return JSONResponse(body)

    stored_data: dict = stored.get("data") or {}
    stored_hash: str = stored.get("hash") or ""
    all_items = stored_data.get(append_field)
    if not isinstance(all_items, list):
        all_items = []

    if checkpoint > 0:
        # Elements are strictly increasing in ``ts`` — binary search for the first
        # index whose ts > checkpoint, then return that suffix.
        element_ts = [
            el["ts"] if isinstance(el, dict) and isinstance(el.get("ts"), int) else 0
            for el in all_items
        ]
        lo = bisect.bisect_right(element_ts, checkpoint)
        filtered_items = all_items[lo:]
    else:
        filtered_items = all_items

    if last is not None:
        filtered_items = [] if last == 0 else filtered_items[-last:]

    response_data = {**stored_data, append_field: filtered_items}
    body = {"data": response_data, "hash": stored_hash, "timestamp": now}

    headers = {}
    if cache_duration_ms is not None:
        max_age = cache_duration_ms // 1000
        directive = f"max-age={max_age}" if is_public else f"private, max-age={max_age}"
        headers["Cache-Control"] = directive
    if stored_hash:
        headers["ETag"] = f'"{stored_hash}"'

    return JSONResponse(body, headers=headers if headers else None)


async def handle_sync_push(
    document_key: str,
    store: AbstractObjectStore,
    body: dict[str, Any],
    identity: str | None = None,
    skip_timestamps: bool = False,
    skip_storage: bool = False,
    context: StoreContext | None = None,
) -> JSONResponse:
    if is_unsafe_document_key(document_key):
        return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

    data = body.get("data")
    base_hash = body.get("baseHash")
    author_signature = body.get("authorSignature")

    if not isinstance(data, dict):
        return JSONResponse({"error": "Missing or invalid data"}, status_code=400)

    if base_hash is not None and not isinstance(base_hash, str):
        return JSONResponse({"error": "baseHash must be a string or null"}, status_code=400)

    sanitized = deep_sanitize(data)

    author: Author | None = None
    if isinstance(author_signature, str) and identity:
        author = Author(pubkey=identity, signature=author_signature)

    result = await push(store, document_key, sanitized, base_hash, author, skip_timestamps, skip_storage, context=context)

    if not isinstance(result, PushSuccess):
        return JSONResponse({"error": ERROR_HASH_MISMATCH}, status_code=409)

    return JSONResponse({"hash": result.hash, "timestamp": result.timestamp})
