"""Tests for the in-memory KVAdapter and the K2V adapter (over a mock transport)."""

import json

from starfish_server.storage.kv_adapter import create_in_memory_kv_adapter
from starfish_server.storage.k2v_adapter import create_k2v_adapter, K2VReadResult


# --- in-memory increment ---


async def test_in_memory_increment_counts_and_restarts_after_expiry() -> None:
    clock = {"t": 1_000}
    kv = create_in_memory_kv_adapter(now=lambda: clock["t"])
    assert await kv.increment("k", 60_000) == 1
    assert await kv.increment("k", 60_000) == 2
    clock["t"] += 60_001  # window elapsed
    assert await kv.increment("k", 60_000) == 1  # restarts


async def test_in_memory_increment_isolates_keys() -> None:
    kv = create_in_memory_kv_adapter()
    assert await kv.increment("a", 60_000) == 1
    assert await kv.increment("a", 60_000) == 2
    assert await kv.increment("b", 60_000) == 1


async def test_in_memory_bounds_key_count() -> None:
    # A flood of distinct keys must not grow without bound; the oldest are evicted.
    kv = create_in_memory_kv_adapter(max_keys=8)
    for i in range(200):
        await kv.increment(f"k{i}", 60_000)
    assert await kv.increment("k0", 60_000) == 1  # k0 long evicted → restarts
    assert await kv.increment("k199", 60_000) == 2  # k199 still live


# --- in-memory record_if_absent ---


async def test_in_memory_record_if_absent_rejects_replay_then_accepts_after_expiry() -> None:
    clock = {"t": 1_000}
    kv = create_in_memory_kv_adapter(now=lambda: clock["t"])
    assert await kv.record_if_absent("n", 60_000) is True
    assert await kv.record_if_absent("n", 60_000) is False
    clock["t"] += 60_001
    assert await kv.record_if_absent("n", 60_000) is True


async def test_in_memory_record_if_absent_group_cap_fails_closed() -> None:
    kv = create_in_memory_kv_adapter()
    assert await kv.record_if_absent("a1", 60_000, ("A", 2)) is True
    assert await kv.record_if_absent("a2", 60_000, ("A", 2)) is True
    assert await kv.record_if_absent("a3", 60_000, ("A", 2)) is False  # at cap
    assert await kv.record_if_absent("b1", 60_000, ("B", 2)) is True  # other group unaffected


# --- K2V adapter over a mock transport ---


class _MockTransport:
    """Stores siblings per (pk, sk); read returns all of them, insert supersedes/appends."""

    def __init__(self) -> None:
        self.siblings: dict[str, list[str]] = {}
        self._token = 0

    async def read(self, pk: str, sk: str) -> K2VReadResult:
        vals = list(self.siblings.get(f"{pk}/{sk}", []))
        return K2VReadResult(values=vals, causality=(f"t{self._token}" if vals else None))

    async def insert(self, pk: str, sk: str, value: str, causality) -> None:
        key = f"{pk}/{sk}"
        if causality:
            self.siblings[key] = [value]  # superseding write replaces siblings
        else:
            self.siblings.setdefault(key, []).append(value)  # concurrent → new sibling
        self._token += 1


async def test_k2v_increment_counts_up_and_restarts() -> None:
    clock = {"t": 1_000}
    kv = create_k2v_adapter(_MockTransport(), now=lambda: clock["t"])
    assert await kv.increment("k", 60_000) == 1
    assert await kv.increment("k", 60_000) == 2
    assert await kv.increment("k", 60_000) == 3
    clock["t"] += 60_001
    assert await kv.increment("k", 60_000) == 1  # expired siblings ignored → restart


async def test_k2v_increment_sums_concurrent_siblings() -> None:
    t = _MockTransport()
    kv = create_k2v_adapter(t, now=lambda: 1_000)
    # Two concurrent increments both read absent and wrote sibling "1"s.
    t.siblings["starfish-kv/k"] = [
        json.dumps({"exp": 61_000, "n": 1}),
        json.dumps({"exp": 61_000, "n": 1}),
    ]
    # Next increment sums siblings (1 + 1) + 1 = 3 (stricter than the "true" count).
    assert await kv.increment("k", 60_000) == 3


async def test_k2v_record_if_absent() -> None:
    clock = {"t": 1_000}
    kv = create_k2v_adapter(_MockTransport(), now=lambda: clock["t"])
    assert await kv.record_if_absent("n", 60_000) is True
    assert await kv.record_if_absent("n", 60_000) is False
    clock["t"] += 60_001
    assert await kv.record_if_absent("n", 60_000) is True
