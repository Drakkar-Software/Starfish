"""Append-only transform helper for the Starfish sync protocol."""

import json
import logging
from typing import Any

from starfish_protocol.hash import compute_hash
from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.protocol.types import Timestamps

logger = logging.getLogger(__name__)


async def build_append_only_data(
    store: AbstractObjectStore,
    document_key: str,
    new_item: dict[str, Any],
    append_field: str,
    now: int,
    context: StoreContext | None = None,
) -> tuple[dict[str, Any], str, Timestamps, str]:
    """Read existing doc, append new_item, return (new_data, base_hash, timestamps, last_item_hash).

    ``timestamps`` is the full timestamps tree to store directly: the
    append_field entry becomes a ``list[int]`` parallel to the array.
    ``last_item_hash`` is ``compute_hash({"n": len, "last": new_item})`` — O(1).
    """
    raw = await store.get_string(document_key, context=context)

    if not raw:
        last_item_hash = compute_hash({"n": 1, "last": new_item})
        return (
            {append_field: [new_item]},
            "",
            {append_field: [now]},
            last_item_hash,
        )

    existing_data: dict[str, Any] = {}
    base_hash = ""
    existing_timestamps: Timestamps = {}

    try:
        doc = json.loads(raw)
        existing_data = doc.get("data") or {}
        base_hash = doc.get("hash") or ""
        existing_timestamps = doc.get("timestamps") or {}
    except (json.JSONDecodeError, AttributeError) as exc:
        logger.error("Corrupt stored document at key %r: %s", document_key, exc)
        last_item_hash = compute_hash({"n": 1, "last": new_item})
        return (
            {append_field: [new_item]},
            "",
            {append_field: [now]},
            last_item_hash,
        )

    existing = existing_data.get(append_field)
    arr = existing if isinstance(existing, list) else []
    new_arr = [*arr, new_item]

    # Per-item timestamps: preserve existing list or backfill with now for legacy docs
    prev_ts = existing_timestamps.get(append_field)
    is_valid_ts = isinstance(prev_ts, list) and all(isinstance(t, int) for t in prev_ts)
    if is_valid_ts and len(prev_ts) != len(arr):
        logger.warning(
            "Timestamp/items length mismatch at key %r (%d vs %d); backfilling",
            document_key, len(prev_ts), len(arr),
        )
    if is_valid_ts and len(prev_ts) == len(arr):
        item_ts = [*prev_ts, now]
    else:
        item_ts = [now] * len(arr) + [now]

    last_item_hash = compute_hash({"n": len(new_arr), "last": new_item})

    return (
        {**existing_data, append_field: new_arr},
        base_hash,
        {**existing_timestamps, append_field: item_ts},
        last_item_hash,
    )


async def check_last_item_conflict(
    store: AbstractObjectStore,
    document_key: str,
    client_base_hash: str | None,
    _append_field: str,
    context: StoreContext | None = None,
) -> str | None:
    """Compare client_base_hash against the stored document hash.

    For appendOnly collections the stored hash is ``compute_hash({"n", "last"})``
    — the client should pass back the hash received from the last pull response.

    Returns ``None`` (no conflict) or ``"hash_mismatch"``.

    Not called by the route-builder (the check runs inline inside the retry loop
    using the base_hash already returned by build_append_only_data). Exported as
    a utility for callers that manage their own retry logic.
    """
    raw = await store.get_string(document_key, context=context)

    if not raw:
        if client_base_hash and client_base_hash != "":
            return "hash_mismatch"
        return None

    try:
        doc = json.loads(raw)
        stored_hash = doc.get("hash") or ""
        if client_base_hash != stored_hash:
            return "hash_mismatch"
        return None
    except (json.JSONDecodeError, AttributeError):
        return "hash_mismatch"
