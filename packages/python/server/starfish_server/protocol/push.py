"""Push operation for the Starfish sync protocol."""


import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from starfish_server.storage.base import AbstractObjectStore
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
    store: AbstractObjectStore,
    document_key: str,
    new_data: dict[str, Any],
    base_hash: str | None,
    author: Author | None = None,
    skip_timestamps: bool = False,
    skip_storage: bool = False,
    precomputed_hash: str | None = None,
    precomputed_timestamps: dict | None = None,
) -> PushResult:
    """Push a new full document.

    - Compares base_hash with current document hash
    - Match -> accept, compute timestamp diffs, store
    - Mismatch -> reject with hash_mismatch
    - base_hash: None for first push (no existing document expected)
    - skip_storage: when True, skip storage read/write and return hash+timestamp directly
    """
    if skip_storage:
        now = time.time_ns() // 1_000_000
        new_hash = precomputed_hash if precomputed_hash is not None else compute_hash(new_data)
        return PushSuccess(hash=new_hash, timestamp=now)

    raw = await store.get_string(document_key)

    old_data: dict[str, Any] | None = None
    old_timestamps = None
    current_hash = ""

    if raw:
        try:
            existing = json.loads(raw)
            old_data = existing["data"]
            old_timestamps = existing["timestamps"]
            current_hash = existing["hash"]
        except (json.JSONDecodeError, KeyError) as exc:
            logging.getLogger(__name__).error(
                "Corrupt stored document at key %r: %s", document_key, exc
            )
            # Treat as empty — current_hash stays "" which allows recovery via baseHash=""

    # Hash check
    if base_hash is None:
        if raw:
            return PushConflict(error=ERROR_HASH_MISMATCH)
    else:
        if base_hash != current_hash:
            return PushConflict(error=ERROR_HASH_MISMATCH)

    now = time.time_ns() // 1_000_000
    new_hash = precomputed_hash if precomputed_hash is not None else compute_hash(new_data)
    if skip_timestamps:
        timestamps: dict = {}
    elif precomputed_timestamps is not None:
        timestamps = precomputed_timestamps
    else:
        timestamps = compute_timestamps(old_data, new_data, old_timestamps, now)

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
