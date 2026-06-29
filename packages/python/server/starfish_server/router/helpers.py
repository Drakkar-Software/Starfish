"""Request handling helpers for sync routes."""


import asyncio
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

from starfish_protocol.append_author import verify_doc_author
from starfish_protocol.merge import UNSAFE_KEYS
from starfish_protocol.constants import (
    AUTHOR_PUBKEY_FIELD,
    AUTHOR_SIGNATURE_FIELD,
    DATA_FIELD,
    BASE_HASH_FIELD,
)
from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push, append_seg_prefix, append_chunk_key
from starfish_server.protocol.push import Author
from starfish_server.protocol.types import PushSuccess
from starfish_server.constants import (
    QUERY_CHECKPOINT,
    ERROR_HASH_MISMATCH,
    CONTENT_TYPE_JSON,
    APPEND_DEFAULT_FIELD,
    ERROR_PULL_BOUND_REQUIRED,
    ERROR_FULL_WITH_BOUNDS,
    ERROR_FULL_NOT_ALLOWED,
    ERROR_CHECKPOINT_TOO_OLD,
)

logger = logging.getLogger(__name__)

SAFE_PARAM = re.compile(r"^[a-zA-Z0-9._:@-]+$")
UNSAFE_KEY = re.compile(r"\.\.|[\x00-\x1f]|//")

# UNSAFE_KEYS is imported from starfish_protocol.merge (the protocol-shared
# 5-key denylist: __proto__, constructor, prototype, __class__, __dict__).
# Do NOT redefine it here — the TS server sources the same set from
# @drakkar.software/starfish-protocol/unsafe-keys so both languages sanitize
# identical key sets, producing the same content hash for the same document.

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
        body[AUTHOR_PUBKEY_FIELD] = result.author_pubkey
    if result.author_signature:
        body[AUTHOR_SIGNATURE_FIELD] = result.author_signature

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


async def _read_append_chunks(
    store: AbstractObjectStore,
    document_key: str,
    checkpoint: int,
    last: int | None,
    chunk_size: int,
    context: StoreContext | None = None,
) -> list:
    """Read only the chunks a segmented (``chunk_size``) append-only pull needs.

    Each chunk key encodes its first element's ``ts``, so the lexicographically
    sorted key list (one ``list_keys`` call — no chunk contents) tells us every
    chunk's ts range: ``?checkpoint=`` skips chunks entirely at/below it (reading
    only the boundary chunk and those after); ``?last=K`` reads only the final
    ``ceil(K/chunk_size)+1`` chunks. Returns the gathered ``{ts,data}`` envelopes
    in order; the caller's checkpoint/last filtering then trims precisely.
    """
    if last == 0:
        return []
    chunk_keys = await store.list_keys(append_seg_prefix(document_key), context=context)
    if not chunk_keys:
        return []

    start_idx = 0
    if checkpoint > 0:
        # Boundary = last chunk key <= the (same-width) key for the checkpoint ts.
        cp_key = append_chunk_key(document_key, checkpoint)
        lo = bisect.bisect_right(chunk_keys, cp_key)
        start_idx = max(0, lo - 1)  # include the boundary chunk (may hold both <= and > checkpoint)

    needed = chunk_keys[start_idx:]
    if last is not None and last > 0 and chunk_size > 0:
        max_chunks = (last + chunk_size - 1) // chunk_size + 1
        if len(needed) > max_chunks:
            needed = needed[-max_chunks:]

    raws = await asyncio.gather(*(store.get_string(k, context=context) for k in needed))
    items: list = []
    for raw in raws:
        if not raw:
            continue
        try:
            arr = json.loads(raw)
            if isinstance(arr, list):
                items.extend(arr)
        except (json.JSONDecodeError, ValueError) as exc:
            logger.error("Corrupt append-only chunk under %r: %s", document_key, exc)
    return items


async def handle_append_only_pull(
    document_key: str,
    store: AbstractObjectStore,
    checkpoint_param: str | None = None,
    append_field: str = APPEND_DEFAULT_FIELD,
    cache_duration_ms: int | None = None,
    is_public: bool = True,
    last_param: str | None = None,
    context: StoreContext | None = None,
    limit_param: str | None = None,
    full_param: str | None = None,
    allow_full: bool = True,
    max_pull_limit: int | None = None,
    max_checkpoint_age_ms: int | None = None,
) -> JSONResponse:
    """Pull handler for appendOnly persist=true collections.

    A pull MUST declare how much it fetches: one of ``?checkpoint=`` (incremental),
    ``?limit=``/``?last=`` (tail of K), or ``?full=true`` (the whole collection).
    An unbounded pull is rejected ``400 pull_bound_required``; ``?full=true`` cannot
    be combined with a bound (``400 full_with_bounds``). ``limit`` is an alias of
    ``last`` (tail of K, newest); when both are given, ``limit`` wins.

    Each stored element is a ``{ts, data}`` envelope. With a checkpoint, returns
    only elements whose ``ts`` is strictly greater than it, found by binary search
    (the array is strictly increasing in ``ts``); the tail bound then trims to the
    last K. The full ``{ts, data}`` envelopes are returned — ``data`` is plaintext
    under "none" and an encryptor wrapper under "delegated".
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

    # ``limit`` is an alias of ``last``; when both are present, ``limit`` wins.
    last: int | None = None
    for name, raw in (("limit", limit_param), ("last", last_param)):
        if raw is None:
            continue
        try:
            parsed_tail = int(raw)
        except ValueError:
            return JSONResponse({"error": f"Invalid {name}"}, status_code=400)
        if parsed_tail < 0 or str(parsed_tail) != raw:
            return JSONResponse({"error": f"Invalid {name}"}, status_code=400)
        last = parsed_tail
        if name == "limit":
            break

    full = full_param in ("true", "1")

    # A pull must declare its bound. ``checkpoint=0`` counts as present (explicit
    # "from the start") — only a fully absent set of params is rejected.
    if checkpoint_param is None and last is None and not full:
        return JSONResponse({"error": ERROR_PULL_BOUND_REQUIRED}, status_code=400)
    if full and (checkpoint_param is not None or last is not None):
        return JSONResponse({"error": ERROR_FULL_WITH_BOUNDS}, status_code=400)
    if full and not allow_full:
        return JSONResponse({"error": ERROR_FULL_NOT_ALLOWED}, status_code=400)

    now = int(time.time() * 1000)

    if (
        checkpoint_param is not None
        and max_checkpoint_age_ms is not None
        and checkpoint < now - max_checkpoint_age_ms
    ):
        return JSONResponse({"error": ERROR_CHECKPOINT_TOO_OLD}, status_code=400)

    # Clamp the requested tail to the collection cap.
    if last is not None and max_pull_limit is not None and last > max_pull_limit:
        last = max_pull_limit
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
    # Segmented (``seg``) docs keep the array in sibling chunk objects; read only the
    # chunks the checkpoint/last needs. Legacy single-docs keep the array inline.
    if stored.get("seg") is True:
        all_items = await _read_append_chunks(
            store, document_key, checkpoint, last, stored.get("chunkSize") or 0, context
        )
    else:
        all_items = stored_data.get(append_field)
        if not isinstance(all_items, list):
            all_items = []

    if checkpoint > 0:
        # Elements are strictly increasing in ``ts`` — binary search for the first
        # index whose ts > checkpoint, then return that suffix. ``key=`` reads ts
        # lazily during the search (O(log n) calls) — no full pre-pass over the array.
        lo = bisect.bisect_right(
            all_items,
            checkpoint,
            key=lambda el: el["ts"] if isinstance(el, dict) and isinstance(el.get("ts"), int) else 0,
        )
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
    presenter: Any = None,
) -> JSONResponse:
    if is_unsafe_document_key(document_key):
        return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

    data = body.get(DATA_FIELD)
    base_hash = body.get(BASE_HASH_FIELD)
    author_pubkey = body.get(AUTHOR_PUBKEY_FIELD)
    author_signature = body.get(AUTHOR_SIGNATURE_FIELD)

    if not isinstance(data, dict):
        return JSONResponse({"error": "Missing or invalid data"}, status_code=400)

    if base_hash is not None and not isinstance(base_hash, str):
        return JSONResponse({"error": "baseHash must be a string or null"}, status_code=400)

    sanitized = deep_sanitize(data)

    # Document author proof (verify-if-present). When a client signs the push (a
    # ``SyncManager`` signer is configured), the proof rides as top-level body
    # fields: verify it over the stored data (bound to document_key), require the
    # author to be the authenticated request presenter, and store the RAW author
    # pubkey. Absent proof is accepted (an unsigned merge-doc push is unchanged).
    author: Author | None = None
    if author_pubkey is not None or author_signature is not None:
        if not isinstance(author_pubkey, str) or not isinstance(author_signature, str):
            return JSONResponse(
                {"error": "author proof requires authorPubkey and authorSignature"},
                status_code=400,
            )
        if presenter is not None and author_pubkey != presenter.pub_hex:
            return JSONResponse(
                {"error": "document author must be the request presenter"}, status_code=403
            )
        if not verify_doc_author(
            document_key, sanitized, author_pubkey, author_signature
        ):
            return JSONResponse(
                {"error": "invalid document author signature"}, status_code=403
            )
        author = Author(pubkey=author_pubkey, signature=author_signature)

    result = await push(store, document_key, sanitized, base_hash, author, skip_timestamps, skip_storage, context=context)

    if not isinstance(result, PushSuccess):
        # Include currentHash so clients can retry without a second (potentially stale) pull.
        return JSONResponse({"error": ERROR_HASH_MISMATCH, "currentHash": result.current_hash}, status_code=409)

    return JSONResponse({"hash": result.hash, "timestamp": result.timestamp})
