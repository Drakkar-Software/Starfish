"""KVAdapter backed by Garage K2V.

Mirror of ``packages/ts/server/src/storage/k2v-adapter.ts``. See that file's header for the
full consistency rationale. K2V has NO compare-and-set, NO atomic increment, and NO native
key expiry: concurrent writes become "siblings" merged by the reader via an
``X-Garage-Causality-Token``. This adapter therefore:

  - embeds an ``exp`` (ms) in every value and treats expired-on-read entries as absent
    (logically expired keys linger in K2V until overwritten or externally pruned);
  - on ``increment``, sums all live siblings and writes back the merged total superseding
    the read causality token. Concurrent increments may briefly **overcount** (stricter,
    fail-closed) — never undercount;
  - on ``record_if_absent``, does a best-effort read-then-write (no CAS → a narrow
    concurrent-duplicate replay window). The ``group`` fail-closed cap is **ignored**.

The HTTP/auth boundary is an injectable transport, so the protocol logic here is testable
with a mock and you can supply auth (AWS SigV4, a proxy, etc.) however you like.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Callable, Protocol


@dataclass
class K2VReadResult:
    """Result of a K2V ReadItem: the live + tombstone sibling values and causality token."""

    values: list[str]
    causality: str | None


class K2VTransport(Protocol):
    """The HTTP/auth boundary for :func:`create_k2v_adapter`."""

    async def read(self, partition_key: str, sort_key: str) -> K2VReadResult:
        """ReadItem ``(partition_key, sort_key)`` → sibling values + causality token."""
        ...

    async def insert(
        self, partition_key: str, sort_key: str, value: str, causality: str | None
    ) -> None:
        """InsertItem, superseding ``causality`` when provided."""
        ...


def _parse_value(raw: str) -> dict | None:
    try:
        v = json.loads(raw)
        return v if isinstance(v, dict) and isinstance(v.get("exp"), (int, float)) else None
    except (ValueError, TypeError):
        return None


class _K2VAdapter:
    def __init__(
        self,
        transport: K2VTransport,
        partition_key: str = "starfish-kv",
        now: Callable[[], float] | None = None,
    ) -> None:
        self._t = transport
        self._pk = partition_key
        self._now = now or (lambda: time.time() * 1000)

    async def increment(self, key: str, ttl_ms: int) -> int:
        result = await self._t.read(self._pk, key)
        t = self._now()
        total = 0
        for raw in result.values:
            v = _parse_value(raw)
            if v is not None and v["exp"] > t:
                total += int(v.get("n", 0))
        nxt = total + 1
        await self._t.insert(
            self._pk, key, json.dumps({"exp": t + ttl_ms, "n": nxt}), result.causality
        )
        return nxt

    async def record_if_absent(
        self, key: str, ttl_ms: int, group: tuple[str, int] | None = None
    ) -> bool:
        result = await self._t.read(self._pk, key)
        t = self._now()
        live = any(
            (v := _parse_value(raw)) is not None and v["exp"] > t for raw in result.values
        )
        if live:
            return False
        await self._t.insert(self._pk, key, json.dumps({"exp": t + ttl_ms}), result.causality)
        return True


def create_k2v_adapter(
    transport: K2VTransport,
    *,
    partition_key: str = "starfish-kv",
    now: Callable[[], float] | None = None,
) -> "_K2VAdapter":
    """Build a KVAdapter over Garage K2V. See the module header for consistency caveats
    (overcount under contention; best-effort replay protection without CAS)."""
    return _K2VAdapter(transport, partition_key, now)


__all__ = ["K2VTransport", "K2VReadResult", "create_k2v_adapter"]
