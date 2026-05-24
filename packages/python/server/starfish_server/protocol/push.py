"""Push and append operations for the Starfish sync protocol."""


import asyncio
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

# Per-key asyncio lock registry. Serialises concurrent writes to the same
# document_key so the read-check-write triplet is atomic under asyncio.
# defaultdict is safe — asyncio is single-threaded per event loop.
# Both `push` (regular) and `append_item` (appendOnly) share this registry so
# they serialise against each other on the same key.
_push_locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

from starfish_server.storage.base import AbstractObjectStore, StoreContext
from starfish_server.constants import ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON
from starfish_server.protocol.types import (
    StoredDocument,
    AppendElement,
    PushSuccess,
    PushConflict,
    PushResult,
    DOCUMENT_VERSION,
)
from starfish_protocol.hash import compute_hash


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
    context: StoreContext | None = None,
) -> PushResult:
    """Push a new full document.

    - Compares base_hash with current document hash
    - Match -> accept and store with a single document-level write ``ts``
    - Mismatch -> reject with hash_mismatch
    - base_hash: None for first push (no existing document expected)
    - skip_storage: when True, skip storage read/write and return hash+timestamp directly

    ``skip_timestamps`` is retained as an inert no-op for call-site compatibility;
    the per-field ``timestamps`` tree was removed (a document carries only the
    doc-level ``ts``).
    """
    if skip_storage:
        now = time.time_ns() // 1_000_000
        new_hash = precomputed_hash if precomputed_hash is not None else compute_hash(new_data)
        return PushSuccess(hash=new_hash, timestamp=now)

    async with _push_locks[document_key]:  # serialise concurrent pushes per key
        return await _push_locked(
            store, document_key, new_data, base_hash, author,
            precomputed_hash, context,
        )


async def _push_locked(
    store: AbstractObjectStore,
    document_key: str,
    new_data: dict[str, Any],
    base_hash: str | None,
    author: "Author | None",
    precomputed_hash: str | None,
    context: "StoreContext | None" = None,
) -> PushResult:
    raw = await store.get_string(document_key, context=context)

    current_hash = ""

    if raw:
        try:
            existing = json.loads(raw)
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

    doc: dict[str, Any] = {
        "v": DOCUMENT_VERSION,
        "data": new_data,
        "ts": now,
        "hash": new_hash,
    }
    if author:
        doc["authorPubkey"] = author.pubkey
        doc["authorSignature"] = author.signature

    await store.put(document_key, json.dumps(doc), content_type=CONTENT_TYPE_JSON, context=context)

    return PushSuccess(hash=new_hash, timestamp=now)


@dataclass
class AppendConflict:
    """Conflict returned by :func:`append_item` when a client-supplied ``ts`` is
    not strictly greater than the most recent element's ``ts``."""

    latest: int
    error: str = "non_monotonic_timestamp"


AppendOutcome = PushSuccess | AppendConflict


def _element_ts(el: Any) -> int:
    if isinstance(el, dict) and isinstance(el.get("ts"), int):
        return el["ts"]
    return -1


async def append_item(
    store: AbstractObjectStore,
    document_key: str,
    item: Any,
    append_field: str,
    provided_ts: int | None = None,
    context: StoreContext | None = None,
) -> AppendOutcome:
    """Append one element to an appendOnly (``by_timestamp``) collection.

    Runs the read -> ts-resolve -> append -> write triplet inside the per-key
    :data:`_push_locks` lock (shared with :func:`push`) so concurrent appends
    serialise and never lose an element — this replaces the old ``base_hash``
    hash-mismatch check, which is no longer used for appendOnly (an authorized
    append is always accepted, content-wise).

    Timestamp rules (let ``latest`` = ``ts`` of the last stored element, or ``-1``
    if empty):

    - ``provided_ts`` given -> require ``provided_ts > latest`` (else
      ``non_monotonic_timestamp``); store the element verbatim with ``provided_ts``.
    - ``provided_ts`` omitted -> store with ``max(now, latest + 1)``, which keeps
      the array strictly increasing in ``ts`` (so the pull-side checkpoint binary
      search stays valid) even after a client previously stored a future ``ts``.

    ``item`` (the element payload) is stored opaquely — plaintext under ``"none"``,
    an encryptor wrapper under ``"delegated"``. The stored document ``hash`` is
    ``compute_hash({"n", "last"})`` where ``last`` is ``item`` only (not the
    ``{ts, data}`` envelope).
    """
    async with _push_locks[document_key]:  # serialise concurrent appends per key
        return await _append_locked(
            store, document_key, item, append_field, provided_ts, context,
        )


async def _append_locked(
    store: AbstractObjectStore,
    document_key: str,
    item: Any,
    append_field: str,
    provided_ts: int | None,
    context: "StoreContext | None" = None,
) -> AppendOutcome:
    raw = await store.get_string(document_key, context=context)

    existing_data: dict[str, Any] = {}
    if raw:
        try:
            doc = json.loads(raw)
            existing_data = doc.get("data") or {}
        except (json.JSONDecodeError, AttributeError) as exc:
            logging.getLogger(__name__).error(
                "Corrupt stored document at key %r: %s", document_key, exc
            )
            existing_data = {}

    existing = existing_data.get(append_field)
    arr = existing if isinstance(existing, list) else []
    latest = _element_ts(arr[-1]) if arr else -1

    now = time.time_ns() // 1_000_000
    if provided_ts is not None:
        if not (provided_ts > latest):
            return AppendConflict(latest=latest)
        ts = provided_ts
    else:
        ts = max(now, latest + 1)

    element: AppendElement = {"ts": ts, "data": item}
    new_arr = [*arr, element]
    new_hash = compute_hash({"n": len(new_arr), "last": item})

    doc_out: dict[str, Any] = {
        "v": DOCUMENT_VERSION,
        "data": {**existing_data, append_field: new_arr},
        "ts": ts,
        "hash": new_hash,
    }

    await store.put(document_key, json.dumps(doc_out), content_type=CONTENT_TYPE_JSON, context=context)

    return PushSuccess(hash=new_hash, timestamp=ts)
