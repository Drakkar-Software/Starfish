"""Tests for the replay-protection nonce cache (in-memory + KVAdapter-backed)."""

import pytest

from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache, create_kv_nonce_cache
from starfish_server.storage.kv_adapter import create_in_memory_kv_adapter


async def test_fresh_nonce_accepted_then_replay_rejected() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert await cache.check_and_remember("signer-a", "nonce-1", now) is True
    assert await cache.check_and_remember("signer-a", "nonce-1", now + 100) is False


async def test_nonce_accepted_again_after_window() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert await cache.check_and_remember("signer-a", "nonce-1", now) is True
    assert await cache.check_and_remember("signer-a", "nonce-1", now + 60_001) is True


async def test_replay_rejected_at_exact_expiry_instant() -> None:
    # The window is 2× the clock skew; a clock-ahead request that first arrives
    # skew-early can be replayed exactly skew-late, landing on now + window_ms.
    # That instant must still count as a replay, or the slot re-opens.
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert await cache.check_and_remember("s", "n", now) is True
    assert await cache.check_and_remember("s", "n", now + 60_000) is False
    assert await cache.check_and_remember("s", "n", now + 60_001) is True


async def test_nonces_scoped_per_signer() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert await cache.check_and_remember("signer-a", "nonce-x", now) is True
    assert await cache.check_and_remember("signer-b", "nonce-x", now) is True


async def test_max_entries_fails_closed_never_evicts_live() -> None:
    # A live nonce is never evicted; a full cache rejects new nonces.
    cache = create_in_memory_nonce_cache(window_ms=60_000, max_entries=3)
    now = 1_000_000
    assert await cache.check_and_remember("s", "n1", now) is True
    assert await cache.check_and_remember("s", "n2", now) is True
    assert await cache.check_and_remember("s", "n3", now) is True
    # Full of LIVE entries → a fourth is rejected (n1 is NOT evicted).
    assert await cache.check_and_remember("s", "n4", now) is False
    # n1 still remembered → replay still rejected (the security property).
    assert await cache.check_and_remember("s", "n1", now) is False


async def test_expired_entries_reclaim_capacity() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, max_entries=2)
    now = 1_000_000
    assert await cache.check_and_remember("s", "n1", now) is True
    assert await cache.check_and_remember("s", "n2", now) is True
    assert await cache.check_and_remember("s", "n3", now) is False  # full of live entries
    # After the window elapses, n1/n2 expire and capacity frees up.
    assert await cache.check_and_remember("s", "n3", now + 60_001) is True


async def test_default_options() -> None:
    cache = create_in_memory_nonce_cache()
    now = 12345
    assert await cache.check_and_remember("s", "n", now) is True
    assert await cache.check_and_remember("s", "n", now) is False


async def test_default_window_spans_at_least_twice_the_skew() -> None:
    cache = create_in_memory_nonce_cache()
    now = 5_000_000
    assert await cache.check_and_remember("s", "n", now) is True
    # Still remembered just under 10 minutes later (replayable under the old
    # 5-min window).
    assert await cache.check_and_remember("s", "n", now + 9 * 60_000) is False
    # Past the 10-minute window it is finally forgotten.
    assert await cache.check_and_remember("s", "n", now + 10 * 60_000 + 1) is True


# --- per-signer cap ---


async def test_per_signer_limit_fails_closed_never_evicts_live() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, per_signer_limit=4)
    now = 1_000_000
    for k in ("a1", "a2", "a3", "a4"):
        assert await cache.check_and_remember("A", k, now) is True
    # A is at its cap with all-live entries → fifth nonce rejected.
    assert await cache.check_and_remember("A", "a5", now) is False
    # a1 was NOT evicted → replaying it is still rejected.
    assert await cache.check_and_remember("A", "a1", now) is False


async def test_per_signer_limit_does_not_affect_other_signers() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, per_signer_limit=2)
    now = 1_000_000
    # Signer B parks two nonces first (at its cap).
    assert await cache.check_and_remember("B", "b1", now) is True
    assert await cache.check_and_remember("B", "b2", now) is True
    # Signer A saturates its own cap; A's overflow is rejected.
    assert await cache.check_and_remember("A", "a1", now) is True
    assert await cache.check_and_remember("A", "a2", now) is True
    assert await cache.check_and_remember("A", "a3", now) is False
    # B's nonces are untouched — still live, so replays are rejected.
    assert await cache.check_and_remember("B", "b1", now) is False
    assert await cache.check_and_remember("B", "b2", now) is False
    # Once B's entries expire, B can record a fresh nonce again.
    assert await cache.check_and_remember("B", "b3", now + 60_001) is True


# --- KVAdapter-backed nonce cache ---


async def test_kv_nonce_cache_records_once_and_rejects_replay() -> None:
    clock = {"t": 1_000_000}
    kv = create_in_memory_kv_adapter(now=lambda: clock["t"])
    cache = create_kv_nonce_cache(kv, window_ms=60_000)
    assert await cache.check_and_remember("s", "n", clock["t"]) is True
    assert await cache.check_and_remember("s", "n", clock["t"]) is False  # replay
    clock["t"] += 60_001
    assert await cache.check_and_remember("s", "n", clock["t"]) is True  # window elapsed


async def test_kv_nonce_cache_scopes_per_signer() -> None:
    kv = create_in_memory_kv_adapter()
    cache = create_kv_nonce_cache(kv, window_ms=60_000)
    assert await cache.check_and_remember("signer-a", "x", 1) is True
    assert await cache.check_and_remember("signer-b", "x", 1) is True  # different signer


async def test_kv_nonce_cache_honors_per_signer_cap() -> None:
    kv = create_in_memory_kv_adapter()
    cache = create_kv_nonce_cache(kv, window_ms=60_000, per_signer_limit=2)
    assert await cache.check_and_remember("A", "a1", 1) is True
    assert await cache.check_and_remember("A", "a2", 1) is True
    assert await cache.check_and_remember("A", "a3", 1) is False  # at per-signer cap
