"""Tests for the in-memory replay-protection nonce cache."""

import pytest

from starfish_server.auth.nonce_cache import create_in_memory_nonce_cache


def test_fresh_nonce_accepted_then_replay_rejected() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert cache.check_and_remember("signer-a", "nonce-1", now) is True
    assert cache.check_and_remember("signer-a", "nonce-1", now + 100) is False


def test_nonce_accepted_again_after_window() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert cache.check_and_remember("signer-a", "nonce-1", now) is True
    assert cache.check_and_remember("signer-a", "nonce-1", now + 60_001) is True


def test_replay_rejected_at_exact_expiry_instant() -> None:
    # The window is 2× the clock skew; a clock-ahead request that first arrives
    # skew-early can be replayed exactly skew-late, landing on now + window_ms.
    # That instant must still count as a replay, or the slot re-opens.
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert cache.check_and_remember("s", "n", now) is True
    assert cache.check_and_remember("s", "n", now + 60_000) is False
    assert cache.check_and_remember("s", "n", now + 60_001) is True


def test_nonces_scoped_per_signer() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000)
    now = 1_000_000
    assert cache.check_and_remember("signer-a", "nonce-x", now) is True
    assert cache.check_and_remember("signer-b", "nonce-x", now) is True


def test_max_entries_fails_closed_never_evicts_live() -> None:
    # A live nonce is never evicted; a full cache rejects new nonces.
    cache = create_in_memory_nonce_cache(window_ms=60_000, max_entries=3)
    now = 1_000_000
    assert cache.check_and_remember("s", "n1", now) is True
    assert cache.check_and_remember("s", "n2", now) is True
    assert cache.check_and_remember("s", "n3", now) is True
    # Full of LIVE entries → a fourth is rejected (n1 is NOT evicted).
    assert cache.check_and_remember("s", "n4", now) is False
    # n1 still remembered → replay still rejected (the security property).
    assert cache.check_and_remember("s", "n1", now) is False


def test_expired_entries_reclaim_capacity() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, max_entries=2)
    now = 1_000_000
    assert cache.check_and_remember("s", "n1", now) is True
    assert cache.check_and_remember("s", "n2", now) is True
    assert cache.check_and_remember("s", "n3", now) is False  # full of live entries
    # After the window elapses, n1/n2 expire and capacity frees up.
    assert cache.check_and_remember("s", "n3", now + 60_001) is True


def test_default_options() -> None:
    cache = create_in_memory_nonce_cache()
    now = 12345
    assert cache.check_and_remember("s", "n", now) is True
    assert cache.check_and_remember("s", "n", now) is False


def test_default_window_spans_at_least_twice_the_skew() -> None:
    cache = create_in_memory_nonce_cache()
    now = 5_000_000
    assert cache.check_and_remember("s", "n", now) is True
    # Still remembered just under 10 minutes later (replayable under the old
    # 5-min window).
    assert cache.check_and_remember("s", "n", now + 9 * 60_000) is False
    # Past the 10-minute window it is finally forgotten.
    assert cache.check_and_remember("s", "n", now + 10 * 60_000 + 1) is True


# --- per-signer cap ---


def test_per_signer_limit_fails_closed_never_evicts_live() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, per_signer_limit=4)
    now = 1_000_000
    for k in ("a1", "a2", "a3", "a4"):
        assert cache.check_and_remember("A", k, now) is True
    # A is at its cap with all-live entries → fifth nonce rejected.
    assert cache.check_and_remember("A", "a5", now) is False
    # a1 was NOT evicted → replaying it is still rejected.
    assert cache.check_and_remember("A", "a1", now) is False


def test_per_signer_limit_does_not_affect_other_signers() -> None:
    cache = create_in_memory_nonce_cache(window_ms=60_000, per_signer_limit=2)
    now = 1_000_000
    # Signer B parks two nonces first (at its cap).
    assert cache.check_and_remember("B", "b1", now) is True
    assert cache.check_and_remember("B", "b2", now) is True
    # Signer A saturates its own cap; A's overflow is rejected.
    assert cache.check_and_remember("A", "a1", now) is True
    assert cache.check_and_remember("A", "a2", now) is True
    assert cache.check_and_remember("A", "a3", now) is False
    # B's nonces are untouched — still live, so replays are rejected.
    assert cache.check_and_remember("B", "b1", now) is False
    assert cache.check_and_remember("B", "b2", now) is False
    # Once B's entries expire, B can record a fresh nonce again.
    assert cache.check_and_remember("B", "b3", now + 60_001) is True
