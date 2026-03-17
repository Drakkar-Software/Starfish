"""Request handling helpers for sync routes."""


import ipaddress
import re
from typing import Any, Callable, Awaitable
from urllib.parse import urlparse

from fastapi.responses import JSONResponse

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.protocol.push import Author
from starfish_protocol.hash import stable_stringify
from starfish_server.protocol.types import PushSuccess
from starfish_server.constants import QUERY_CHECKPOINT, ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON

SAFE_PARAM = re.compile(r"^[a-zA-Z0-9._:@-]+$")
UNSAFE_KEY = re.compile(r"\.\.|[\x00-\x1f]|//")

UNSAFE_KEYS = frozenset({"__proto__", "constructor", "prototype"})

SignatureVerifier = Callable[[str, str, str], Awaitable[bool]]


def validate_url_not_private(url: str) -> bool:
    """Return True if the URL does not point to a private/internal network."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except ValueError:
            pass
        return True
    except Exception:  # noqa: BLE001
        return False


def validate_path_segment(value: str) -> bool:
    return bool(SAFE_PARAM.match(value))


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


async def handle_sync_pull(
    document_key: str,
    store: AbstractObjectStore,
    checkpoint_param: str | None = None,
    force_full_fetch: bool = False,
    client_encrypted: bool = False,
) -> JSONResponse:
    if UNSAFE_KEY.search(document_key):
        return JSONResponse({"error": "Invalid path parameter"}, status_code=400)

    checkpoint = 0
    if not force_full_fetch and not client_encrypted and checkpoint_param is not None:
        try:
            parsed = int(checkpoint_param)
        except ValueError:
            return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
        if parsed < 0 or str(parsed) != checkpoint_param:
            return JSONResponse({"error": "Invalid checkpoint"}, status_code=400)
        checkpoint = parsed

    result = await pull(store, document_key, checkpoint)
    body: dict[str, Any] = {
        "data": result.data,
        "hash": result.hash,
        "timestamp": result.timestamp,
    }
    if result.author_pubkey:
        body["authorPubkey"] = result.author_pubkey
    if result.author_signature:
        body["authorSignature"] = result.author_signature

    return JSONResponse(body)


async def handle_sync_push(
    document_key: str,
    store: AbstractObjectStore,
    body: dict[str, Any],
    identity: str | None = None,
    verify_signature: SignatureVerifier | None = None,
    skip_timestamps: bool = False,
) -> JSONResponse:
    if UNSAFE_KEY.search(document_key):
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
    if verify_signature and identity:
        if not isinstance(author_signature, str):
            return JSONResponse({"error": "Missing required author signature"}, status_code=400)
        canonical = stable_stringify(sanitized)
        valid = await verify_signature(canonical, author_signature, identity)
        if not valid:
            return JSONResponse({"error": "Invalid author signature"}, status_code=400)
        author = Author(pubkey=identity, signature=author_signature)
    elif isinstance(author_signature, str) and identity:
        author = Author(pubkey=identity, signature=author_signature)

    result = await push(store, document_key, sanitized, base_hash, author, skip_timestamps)

    if not isinstance(result, PushSuccess):
        return JSONResponse({"error": ERROR_HASH_MISMATCH}, status_code=409)

    return JSONResponse({"hash": result.hash, "timestamp": result.timestamp})
