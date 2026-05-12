"""Concurrent push serialization — per-key lock prevents TOCTOU.

Without a per-key lock, two concurrent pushes that both read the same baseHash
before either write will both pass the hash check and both succeed. The second
write silently overwrites the first — the first client receives a 200 but its
data is gone from the server.

Fix: asyncio.Lock keyed by document_key wraps the read-check-write triplet so
only one push per key runs at a time.
"""

import asyncio
import pytest

from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess, PushConflict
from tests.helpers import MemoryObjectStore


class _YieldingStore(MemoryObjectStore):
    """Inserts an event-loop yield after get_string to expose the TOCTOU window.

    With a real I/O backend, asyncio will naturally yield between the read and
    write. This subclass replicates that behaviour so concurrent-push tests are
    deterministic.
    """

    async def get_string(self, key: str) -> str | None:
        result = await super().get_string(key)
        await asyncio.sleep(0)  # hand control back to the event loop
        return result


@pytest.mark.asyncio
async def test_concurrent_pushes_serialize_one_success_one_conflict():
    """ Two concurrent pushes with the same baseHash → 1 success + 1 conflict.

    Without the lock both coroutines pass the hash check before either write,
    so both succeed (TOCTOU). With the lock the second read sees the updated
    hash and returns 409.
    """
    store = _YieldingStore()
    r0 = await push(store, "col/doc1", {"a": 0}, None)
    assert isinstance(r0, PushSuccess)
    base_hash = r0.hash

    results = await asyncio.gather(
        push(store, "col/doc1", {"a": 1}, base_hash),
        push(store, "col/doc1", {"a": 2}, base_hash),
    )

    successes = [r for r in results if isinstance(r, PushSuccess)]
    conflicts = [r for r in results if isinstance(r, PushConflict)]
    # fix not present → both succeed (TOCTOU) → FAILS
    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}: {results}"
    assert len(conflicts) == 1, f"Expected 1 conflict, got {len(conflicts)}: {results}"


@pytest.mark.asyncio
async def test_sequential_pushes_still_work_after_lock():
    """Regression: serialization must not break the normal sequential push flow."""
    store = _YieldingStore()
    r1 = await push(store, "col/doc1", {"a": 1}, None)
    assert isinstance(r1, PushSuccess)

    r2 = await push(store, "col/doc1", {"a": 2}, r1.hash)
    assert isinstance(r2, PushSuccess)

    r3 = await push(store, "col/doc1", {"a": 3}, "wrong-hash")
    assert isinstance(r3, PushConflict)
