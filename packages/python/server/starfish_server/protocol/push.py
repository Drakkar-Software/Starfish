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
from starfish_server.constants import (
    ERROR_HASH_MISMATCH,
    CONTENT_TYPE_JSON,
    ERROR_APPEND_LIMIT_EXCEEDED,
    APPEND_SEG_SUFFIX,
    APPEND_SEG_TS_WIDTH,
    APPEND_DEFAULT_CHUNK_SIZE,
)
from starfish_server.protocol.types import (
    StoredDocument,
    AppendElement,
    PushSuccess,
    PushConflict,
    PushResult,
    DOCUMENT_VERSION,
)
from starfish_protocol.hash import compute_hash
from starfish_protocol.constants import AUTHOR_PUBKEY_FIELD, AUTHOR_SIGNATURE_FIELD


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

    # Hash check — include current_hash in the conflict response so the client
    # can retry with the authoritative hash without a second (potentially stale) pull.
    if base_hash is None:
        if raw:
            return PushConflict(current_hash=current_hash)
    else:
        if base_hash != current_hash:
            return PushConflict(current_hash=current_hash)

    now = time.time_ns() // 1_000_000
    new_hash = precomputed_hash if precomputed_hash is not None else compute_hash(new_data)

    doc: dict[str, Any] = {
        "v": DOCUMENT_VERSION,
        "data": new_data,
        "ts": now,
        "hash": new_hash,
    }
    if author:
        doc[AUTHOR_PUBKEY_FIELD] = author.pubkey
        doc[AUTHOR_SIGNATURE_FIELD] = author.signature

    await store.put(document_key, json.dumps(doc), content_type=CONTENT_TYPE_JSON, context=context)

    return PushSuccess(hash=new_hash, timestamp=now)


@dataclass
class AppendConflict:
    """Conflict returned by :func:`append_item` when a client-supplied ``ts`` is
    not strictly greater than the most recent element's ``ts``."""

    latest: int
    error: str = "non_monotonic_timestamp"


@dataclass
class AppendLimitExceeded:
    """Returned by :func:`append_item` when the collection's ``max_items`` cap is reached."""

    limit: int
    error: str = ERROR_APPEND_LIMIT_EXCEEDED


AppendOutcome = PushSuccess | AppendConflict | AppendLimitExceeded


# Max compare-and-swap attempts for a single-document append before the conflict
# is surfaced. Only reached under genuine cross-instance contention (the in-process
# per-key lock already serialises same-key writes, so a single instance never retries).
_APPEND_CAS_MAX_ATTEMPTS = 5


class AppendConcurrencyError(Exception):
    """Raised by :func:`append_item` when a conflicting concurrent write from
    another server instance (sharing the same bucket) is detected on every
    compare-and-swap attempt. The append is NOT applied — the conflict is
    surfaced rather than silently overwriting the other instance's write. The
    caller may retry.

    Only reachable when the store supports compare-and-swap
    (:meth:`~starfish_server.storage.base.AbstractObjectStore.get_with_etag` +
    :meth:`~starfish_server.storage.base.AbstractObjectStore.put_if_match`);
    stores without it keep the previous last-write-wins behaviour."""

    def __init__(self, document_key: str, attempts: int) -> None:
        super().__init__(
            f'append_item: concurrent write conflict on "{document_key}" persisted after '
            f"{attempts} compare-and-swap attempts; the append was not applied. Retry the append."
        )


def _store_supports_cas(store: AbstractObjectStore) -> bool:
    """True when ``store`` overrides BOTH conditional-write methods (so the
    default NotImplementedError stubs are not in play)."""
    cls = type(store)
    return (
        cls.get_with_etag is not AbstractObjectStore.get_with_etag
        and cls.put_if_match is not AbstractObjectStore.put_if_match
    )


def _element_ts(el: Any) -> int:
    if isinstance(el, dict) and isinstance(el.get("ts"), int):
        return el["ts"]
    return -1


def append_seg_prefix(document_key: str) -> str:
    """Prefix under which a document's segmented-storage chunks live (a sibling of
    the head key, so the head stays a single object even on the filesystem backend)."""
    return document_key + APPEND_SEG_SUFFIX


def append_chunk_key(document_key: str, first_ts: int) -> str:
    """Key of the chunk whose first element has timestamp ``first_ts``. The ``first_ts``
    is zero-padded so the lexicographically sorted key list is chronological — a pull
    reads the sorted keys once (no chunk contents) to learn every chunk's ts range and
    skip chunks a ``?checkpoint=`` cannot match.

    A negative ``first_ts`` (only reachable by migrating an unsupported ts-less
    legacy element, where ``element_ts`` returns -1) must never form a key: Python
    ``zfill`` puts the sign first (``-000000000000001``) while JS ``padStart`` keeps
    it mid-string (``00000000000000-1``), so the two languages would diverge AND the
    sign would break the lexicographic ordering the bisect relies on. Fail closed so
    any reachable input is byte-identical cross-language."""
    if not isinstance(first_ts, int) or isinstance(first_ts, bool) or first_ts < 0:
        raise ValueError(
            f"append_chunk_key: first_ts must be a non-negative integer, got {first_ts}"
        )
    return append_seg_prefix(document_key) + str(first_ts).zfill(APPEND_SEG_TS_WIDTH)


async def append_item(
    store: AbstractObjectStore,
    document_key: str,
    item: Any,
    append_field: str,
    provided_ts: int | None = None,
    *,
    max_items: int | None = None,
    chunk_size: int | None = None,
    author: "dict[str, str] | None" = None,
    context: StoreContext | None = None,
) -> AppendOutcome:
    """Append one element to an appendOnly (``by_timestamp``) collection.

    Runs the read -> ts-resolve -> append -> write sequence inside the per-key
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

    ``max_items`` (if set) rejects the append once the stored count reaches it
    (:class:`AppendLimitExceeded`). ``chunk_size`` (if set) selects the **segmented**
    layout — the log is stored as fixed-size sealed chunks plus a small head, so an
    append touches only the head and the open tail chunk (O(chunk_size), not O(n));
    a legacy single-doc is lazily migrated into chunks on its next append. Either way
    the wire output is identical: the stored ``hash`` is ``compute_hash({"n", "last"})``
    where ``last`` is ``item`` only, and ``item`` is stored opaquely (plaintext under
    ``"none"``, an encryptor wrapper under ``"delegated"``).
    """
    async with _push_locks[document_key]:  # serialise concurrent appends per key
        return await _append_locked(
            store, document_key, item, append_field, provided_ts,
            max_items, chunk_size, author, context,
        )


def _make_append_element(
    ts: int, item: Any, author: "dict[str, str] | None"
) -> AppendElement:
    """Build an append element, attaching the stored author proof when present.
    The proof is verified by the route layer before storage (signature over
    ``item``, author == request presenter)."""
    element: AppendElement = {"ts": ts, "data": item}
    if author is not None:
        element[AUTHOR_PUBKEY_FIELD] = author[AUTHOR_PUBKEY_FIELD]
        element[AUTHOR_SIGNATURE_FIELD] = author[AUTHOR_SIGNATURE_FIELD]
    return element


async def _append_locked(
    store: AbstractObjectStore,
    document_key: str,
    item: Any,
    append_field: str,
    provided_ts: int | None,
    max_items: int | None,
    chunk_size: int | None,
    author: "dict[str, str] | None" = None,
    context: "StoreContext | None" = None,
) -> AppendOutcome:
    # Cross-instance safety: when the store supports compare-and-swap, the
    # single-document head write below becomes an atomic CAS that fails (and
    # retries) instead of silently overwriting a concurrent instance's append.
    # The in-process per-key lock already serialises same-key writes, so a single
    # instance never hits a CAS failure — this path only engages when two
    # instances share one bucket. Stores without CAS keep last-write-wins.
    #
    # RESIDUAL LIMITATION: only the single-document layout is CAS-protected. The
    # segmented (chunked) layout still uses plain puts on its tail chunk, so two
    # instances appending to the same open tail chunk can still clobber each
    # other. Strict multi-instance guarantees there require either the
    # single-document layout or a CAS-native backend with per-chunk conditional
    # writes (a larger change deliberately left out here).
    cas = _store_supports_cas(store)

    attempt = 0
    while True:
        attempt += 1
        if cas:
            got = await store.get_with_etag(document_key, context=context)
            raw = got[0] if got else None
            head_etag = got[1] if got else None
        else:
            raw = await store.get_string(document_key, context=context)
            head_etag = None

        head: dict[str, Any] | None = None
        if raw:
            try:
                parsed = json.loads(raw)
                head = parsed if isinstance(parsed, dict) else None
            except (json.JSONDecodeError, ValueError) as exc:
                logging.getLogger(__name__).error(
                    "Corrupt stored document at key %r: %s", document_key, exc
                )
                head = None

        is_seg = head is not None and head.get("seg") is True
        existing_data: dict[str, Any] = (head.get("data") if head else None) or {}
        existing = existing_data.get(append_field)
        existing_arr = existing if isinstance(existing, list) else []
        current_count = head.get("n", 0) if is_seg else len(existing_arr)

        # Once a document is segmented it stays segmented, even if chunk_size was later
        # removed from config — otherwise this append would write a fresh single-doc at
        # the head key and orphan every existing chunk (silent data loss). Pull keys off
        # the stored ``seg`` flag the same way.
        if chunk_size is not None:
            effective_chunk_size: int | None = chunk_size
        elif is_seg:
            effective_chunk_size = (head.get("chunkSize") if head else None) or APPEND_DEFAULT_CHUNK_SIZE
        else:
            effective_chunk_size = None

        # Cap check first — never write past the configured limit.
        if max_items is not None and current_count >= max_items:
            return AppendLimitExceeded(limit=max_items)

        if effective_chunk_size is not None:
            # Segmented layout is not CAS-protected (see RESIDUAL LIMITATION above);
            # runs once, plain puts, unchanged behaviour.
            return await _append_chunked(
                store, document_key, item, append_field, provided_ts, effective_chunk_size, head, is_seg, author, context,
            )

        # ---- single-document layout (legacy default) ----
        arr = existing_arr
        latest = _element_ts(arr[-1]) if arr else -1

        now = time.time_ns() // 1_000_000
        if provided_ts is not None:
            if not (provided_ts > latest):
                return AppendConflict(latest=latest)
            ts = provided_ts
        else:
            ts = max(now, latest + 1)

        element: AppendElement = _make_append_element(ts, item, author)
        new_arr = [*arr, element]
        new_hash = compute_hash({"n": len(new_arr), "last": item})

        doc_out: dict[str, Any] = {
            "v": DOCUMENT_VERSION,
            "data": {**existing_data, append_field: new_arr},
            "ts": ts,
            "hash": new_hash,
        }
        body = json.dumps(doc_out)

        if cas:
            new_etag = await store.put_if_match(
                document_key, body, head_etag, content_type=CONTENT_TYPE_JSON, context=context
            )
            if new_etag is None:
                # A concurrent instance changed the head between our read and our
                # write. Re-read and retry rather than overwrite; surface the
                # conflict if the contention persists past the retry budget.
                if attempt >= _APPEND_CAS_MAX_ATTEMPTS:
                    raise AppendConcurrencyError(document_key, attempt)
                continue
        else:
            await store.put(document_key, body, content_type=CONTENT_TYPE_JSON, context=context)

        return PushSuccess(hash=new_hash, timestamp=ts)


async def _append_chunked(
    store: AbstractObjectStore,
    document_key: str,
    item: Any,
    append_field: str,
    provided_ts: int | None,
    chunk_size: int,
    head: dict[str, Any] | None,
    is_seg: bool,
    author: "dict[str, str] | None" = None,
    context: "StoreContext | None" = None,
) -> AppendOutcome:
    """Segmented append (selected by ``chunk_size``). Touches only the head and the
    open tail chunk, so cost is O(chunk_size) regardless of total log size. A legacy
    single-doc (inline ``data[field]`` array, no ``seg``) is sliced into chunks on
    first append (one-time O(n)); thereafter appends are bounded."""
    existing_data: dict[str, Any] = {}
    # ``sealed_n`` = number of elements in all SEALED chunks (everything except
    # the open tail chunk). The total count is ALWAYS re-derived as
    # ``sealed_n + len(tail_arr)``, never read back as a standalone ``n`` — so a
    # head written one append behind (a crash between the chunk write and the
    # head write) self-corrects on the next append for the common, non-roll case:
    # ``sealed_n`` is unchanged by a tail append, and ``tail_arr`` is read
    # authoritatively.
    sealed_n = 0
    tail_key: str | None = None
    tail_arr: list = []
    latest = -1

    if is_seg and head:
        existing_data = head.get("data") or {}
        tail_key = head.get("tailKey")
        if tail_key:
            tail_raw = await store.get_string(tail_key, context=context)
            if tail_raw:
                try:
                    parsed = json.loads(tail_raw)
                    tail_arr = parsed if isinstance(parsed, list) else []
                except (json.JSONDecodeError, ValueError):
                    tail_arr = []
        # Prefer the stored ``sealedN``; fall back to ``n - tailLen`` for a
        # pre-``sealedN`` head (a segmented doc written before this field
        # existed) so the count is preserved across the upgrade.
        stored_sealed_n = head.get("sealedN")
        sealed_n = (
            stored_sealed_n
            if stored_sealed_n is not None
            else max(0, head.get("n", len(tail_arr)) - len(tail_arr))
        )
        # Authoritative ``latest`` from the tail's last element (robust to a stale head).
        latest = _element_ts(tail_arr[-1]) if tail_arr else head.get("ts", -1)
    elif head and isinstance((head.get("data") or {}).get(append_field), list):
        # Lazy-migrate a legacy single-doc into sealed chunks.
        legacy_data = head.get("data") or {}
        legacy_arr = legacy_data[append_field]
        existing_data = {k: v for k, v in legacy_data.items() if k != append_field}
        num_full = len(legacy_arr) // chunk_size
        for c in range(num_full):
            chunk = legacy_arr[c * chunk_size:(c + 1) * chunk_size]
            await store.put(
                append_chunk_key(document_key, _element_ts(chunk[0])),
                json.dumps(chunk), content_type=CONTENT_TYPE_JSON, context=context,
            )
        tail_arr = legacy_arr[num_full * chunk_size:]  # remainder (< chunk_size); written below
        tail_key = append_chunk_key(document_key, _element_ts(tail_arr[0])) if tail_arr else None
        sealed_n = num_full * chunk_size  # full chunks just written are sealed; remainder is the open tail
        latest = _element_ts(legacy_arr[-1]) if legacy_arr else -1
    else:
        # Fresh document (or a non-append doc at this key) — preserve any non-array data.
        existing_data = (head.get("data") if head else None) or {}

    now = time.time_ns() // 1_000_000
    if provided_ts is not None:
        if not (provided_ts > latest):
            return AppendConflict(latest=latest)
        ts = provided_ts
    else:
        ts = max(now, latest + 1)

    element: AppendElement = _make_append_element(ts, item, author)
    if not tail_key or len(tail_arr) >= chunk_size:
        # No open tail, or it is full → the current tail (if any) becomes sealed
        # and a new chunk opens, keyed by this element's ts.
        new_sealed_n = sealed_n + len(tail_arr)
        write_key = append_chunk_key(document_key, ts)
        write_arr: list = [element]
    else:
        # Append to the open tail; the sealed count is unchanged.
        new_sealed_n = sealed_n
        write_key = tail_key
        write_arr = [*tail_arr, element]

    # Count re-derived from authoritative state (sealed chunks + the tail being
    # written), never ``previous_n + 1`` — so it cannot drift across a crash.
    new_n = new_sealed_n + len(write_arr)
    new_hash = compute_hash({"n": new_n, "last": item})

    # Write the chunk first, then the head: a crash in between leaves the head one
    # element behind, but never loses a written element, and the persisted
    # ``sealedN`` lets the next append recompute the true count (non-roll case).
    await store.put(write_key, json.dumps(write_arr), content_type=CONTENT_TYPE_JSON, context=context)
    head_doc: dict[str, Any] = {
        "v": DOCUMENT_VERSION,
        "seg": True,
        "data": existing_data,
        "n": new_n,
        "sealedN": new_sealed_n,
        "ts": ts,
        "hash": new_hash,
        "chunkSize": chunk_size,
        "tailKey": write_key,
    }
    await store.put(document_key, json.dumps(head_doc), content_type=CONTENT_TYPE_JSON, context=context)

    return PushSuccess(hash=new_hash, timestamp=ts)
