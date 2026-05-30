"""Pluggable store for ephemeral, TTL'd server state — rate-limit counters and
replay-protection nonces.

Mirror of ``packages/ts/server/src/storage/kv-adapter.ts``. Defaults to an in-memory
(process-local) implementation that preserves the original behavior; a networked backend
(e.g. Garage K2V, see ``k2v_adapter.py``) shares this state across server instances.

Two purpose-built operations cover both consumers:
  - ``increment`` — fixed-window rate-limit counters (the key's TTL is the window).
  - ``record_if_absent`` — nonce replay protection (record-once within the window).

All operations are async so a networked backend fits the same interface.
"""

from __future__ import annotations

import time
from typing import Callable, Protocol


class KVAdapter(Protocol):
    """Contract for an ephemeral TTL key-value store."""

    async def increment(self, key: str, ttl_ms: int) -> int:
        """Increment the counter at ``key`` (creating it with ``ttl_ms`` when absent or
        expired) and return the new count. Fixed-window rate limiting: the key's TTL is
        the window, so an expired/absent key restarts the count at 1."""
        ...

    async def record_if_absent(
        self, key: str, ttl_ms: int, group: tuple[str, int] | None = None
    ) -> bool:
        """Record ``key`` (with ``ttl_ms``) iff not already present; return ``True`` when
        newly recorded ("fresh"), ``False`` when it already existed ("replay").

        ``group`` = ``(group_key, limit)`` scopes a fail-closed capacity cap: if the group
        already holds ``limit`` live keys, the record is rejected rather than evicting a
        live key. In-memory enforces this; networked backends MAY ignore it."""
        ...


class _InMemoryKVAdapter:
    """Process-local KVAdapter; the default backing for rate limiting and nonces.

    Mirrors the original ``RateLimiter``/``NonceCache`` storage semantics: expired entries
    are reclaimed on access and capacity is bounded by ``max_keys``.
    """

    def __init__(self, max_keys: int = 100_000, now: Callable[[], float] | None = None) -> None:
        self._max_keys = max_keys
        self._now = now or (lambda: time.time() * 1000)
        # key -> (count, expires_at). Insertion order == expiry order.
        self._counters: dict[str, list[float]] = {}
        # store_key -> expires_at, plus per-group live counts for the fail-closed cap.
        self._flags: dict[str, float] = {}
        self._group_counts: dict[str, int] = {}

    def _total_size(self) -> int:
        return len(self._counters) + len(self._flags)

    def _reclaim_expired_counters(self, t: float) -> None:
        expired = []
        for k, entry in self._counters.items():
            if entry[1] > t:
                break
            expired.append(k)
        for k in expired:
            del self._counters[k]

    def _drop_flag(self, store_key: str) -> None:
        self._flags.pop(store_key, None)
        sep = store_key.find(" ")
        if sep > 0:
            group = store_key[:sep]
            c = self._group_counts.get(group)
            if c is not None:
                if c <= 1:
                    self._group_counts.pop(group, None)
                else:
                    self._group_counts[group] = c - 1

    def _evict_oldest_if_full(self) -> None:
        if self._total_size() < self._max_keys:
            return
        # Prefer evicting a counter; fall back to the oldest flag.
        if self._counters:
            del self._counters[next(iter(self._counters))]
            return
        if self._flags:
            self._drop_flag(next(iter(self._flags)))

    async def increment(self, key: str, ttl_ms: int) -> int:
        t = self._now()
        entry = self._counters.get(key)
        if entry is None or entry[1] <= t:
            self._reclaim_expired_counters(t)
            self._evict_oldest_if_full()
            entry = [0, t + ttl_ms]
            self._counters[key] = entry
        entry[0] += 1
        return int(entry[0])

    async def record_if_absent(
        self, key: str, ttl_ms: int, group: tuple[str, int] | None = None
    ) -> bool:
        t = self._now()
        # Group keys are namespaced as ``"{group_key} {key}"`` so _drop_flag can
        # decrement the group counter when an entry expires or is evicted.
        store_key = f"{group[0]} {key}" if group else key
        existing = self._flags.get(store_key)
        if existing is not None:
            if existing >= t:
                return False  # still live → replay
            self._drop_flag(store_key)  # expired → reclaim, fall through

        # Reclaim all expired flags (oldest-first; stop at first live one).
        expired = []
        for k, exp in self._flags.items():
            if exp >= t:
                break
            expired.append(k)
        for k in expired:
            self._drop_flag(k)

        # Fail closed at the group cap (never evict a live nonce).
        if group and self._group_counts.get(group[0], 0) >= group[1]:
            return False
        self._evict_oldest_if_full()

        expiry = t + ttl_ms
        self._flags[store_key] = expiry
        if group:
            self._group_counts[group[0]] = self._group_counts.get(group[0], 0) + 1
        return True


def create_in_memory_kv_adapter(
    *, max_keys: int = 100_000, now: Callable[[], float] | None = None
) -> KVAdapter:
    """Build an in-memory :class:`KVAdapter` (process-local; the default backing).

    :param max_keys: Global cap on live keys, to bound memory under a flood of distinct
        keys (e.g. spoofed X-Forwarded-For). Oldest expired entries are reclaimed first.
    :param now: Injectable clock (ms); defaults to ``time.time() * 1000``.
    """
    return _InMemoryKVAdapter(max_keys, now)


__all__ = ["KVAdapter", "create_in_memory_kv_adapter"]
