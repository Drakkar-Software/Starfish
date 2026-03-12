"""Push operation for the Starfish sync protocol."""


import json
from dataclasses import dataclass
from typing import Any

from starfish_server.interfaces import IObjectStore
from starfish_server.timestamp import next_timestamp
from starfish_server.constants import ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON
from starfish_server.protocol.types import (
    StoredDocument,
    PushSuccess,
    PushConflict,
    PushResult,
    DOCUMENT_VERSION,
)
from starfish_protocol.hash import compute_hash
from starfish_server.protocol.timestamps import compute_timestamps


@dataclass
class Author:
    """Author identity for provenance tracking."""

    pubkey: str
    signature: str


async def push(
    store: IObjectStore,
    document_key: str,
    new_data: dict[str, Any],
    base_hash: str | None,
    author: Author | None = None,
    skip_timestamps: bool = False,
) -> PushResult:
    """Push a new full document.

    - Compares base_hash with current document hash
    - Match -> accept, compute timestamp diffs, store
    - Mismatch -> reject with hash_mismatch
    - base_hash: None for first push (no existing document expected)
    """
    raw = await store.get_string(document_key)

    old_data: dict[str, Any] | None = None
    old_timestamps = None
    current_hash = ""

    if raw:
        existing = json.loads(raw)
        old_data = existing["data"]
        old_timestamps = existing["timestamps"]
        current_hash = existing["hash"]

    # Hash check
    if base_hash is None:
        if raw:
            return PushConflict(error=ERROR_HASH_MISMATCH)
    else:
        if base_hash != current_hash:
            return PushConflict(error=ERROR_HASH_MISMATCH)

    now = next_timestamp()
    new_hash = compute_hash(new_data)
    timestamps = {} if skip_timestamps else compute_timestamps(old_data, new_data, old_timestamps, now)

    doc: dict[str, Any] = {
        "v": DOCUMENT_VERSION,
        "data": new_data,
        "timestamps": timestamps,
        "hash": new_hash,
    }
    if author:
        doc["authorPubkey"] = author.pubkey
        doc["authorSignature"] = author.signature

    await store.put(document_key, json.dumps(doc), content_type=CONTENT_TYPE_JSON)

    return PushSuccess(hash=new_hash, timestamp=now)
