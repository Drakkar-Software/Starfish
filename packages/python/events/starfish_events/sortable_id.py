"""Server-assigned, lexicographically-sortable batch id.

Python mirror of ``packages/ts/events/src/sortable-id.ts``.

The events plugin uses this instead of trusting the client-supplied
``{batchId}`` URL param, so that Starfish's ``/list`` route — which returns
keys in ascending lexicographic order — doubles as a chronological cursor. A
client-minted id can't provide that guarantee: batches are pushed from many
end-user devices with untrusted, possibly-skewed clocks, so a lexicographic
cursor over client timestamps could permanently miss a batch from a
clock-skewed-slow device. Stamping the id from the single server clock at
ingest time avoids that.

Format: ``<13-digit zero-padded epoch-ms>-<4-digit per-ms counter>-<6-hex random>``
e.g. ``0001700000000123-0007-a1b2c3``.

- The epoch-ms segment is fixed-width, so string order matches time order.
- The counter breaks ties for ids minted within the same millisecond by this
  process (wraps at 10000 — astronomically unlikely for a Parquet encode +
  object-store write per request, and a same-value wrap only risks a
  duplicate rank within that millisecond, not an incorrect one).
- The random suffix guarantees the storage key is unique even on a counter
  wrap or a clock that runs backwards.

Ordering is guaranteed only *within one server process*. Multiple sync-server
instances each mint their own monotonic sequence, so cross-instance ordering
isn't guaranteed — callers that need a resumable cursor across a
multi-instance deployment must still dedupe against already-seen ids (as the
SunGlasses dashboard's manifest already does).
"""
from __future__ import annotations

import secrets
import time

_last_ms = 0
_counter = 0


def generate_sortable_batch_id(now_ms: int | None = None) -> str:
    """Generate the next sortable id. ``now_ms`` is injectable for tests."""
    global _last_ms, _counter

    if now_ms is None:
        now_ms = time.time_ns() // 1_000_000

    if now_ms == _last_ms:
        _counter = (_counter + 1) % 10000
    else:
        _last_ms = now_ms
        _counter = 0

    ms_part = str(now_ms).zfill(13)
    counter_part = str(_counter).zfill(4)
    random_part = secrets.token_hex(3)

    return f"{ms_part}-{counter_part}-{random_part}"
