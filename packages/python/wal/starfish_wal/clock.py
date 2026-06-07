"""Causal clock for the WAL CRDT.

Every CRDT op carries a :class:`Clock`: a Lamport counter ``c`` plus a stable,
per-session ``replicaId`` ``r``. The pair ``(c, r)`` is a **total order with no
ties** — two concurrent ops may share a counter but never a replica id, so the
LWW tie-break is always decidable and byte-identical to the TypeScript
implementation (Python compares strings by Unicode code point, matching the
protocol's ``stable_stringify`` key sort).
"""

from __future__ import annotations

from typing import TypedDict


class Clock(TypedDict):
    """A Lamport counter (``c``) tie-broken by a stable replica id (``r``)."""

    c: int
    r: str


def _cmp_str(a: str, b: str) -> int:
    # Python orders strings by Unicode code point already.
    return (a > b) - (a < b)


def compare_clocks(a: Clock, b: Clock) -> int:
    """Total order over clocks: counter first, replica id second.

    Returns a negative/positive int for ``a < b`` / ``a > b`` and ``0`` only when
    the clocks are identical (i.e. the same op, given unique replica ids).
    """
    if a["c"] != b["c"]:
        return a["c"] - b["c"]
    return _cmp_str(a["r"], b["r"])


def clock_greater(a: Clock, b: Clock) -> bool:
    """True iff clock ``a`` strictly dominates ``b``."""
    return compare_clocks(a, b) > 0


class LamportClock:
    """A monotonic Lamport clock for one replica."""

    def __init__(self, replica_id: str, start: int = 0) -> None:
        self.replica_id = replica_id
        self._counter = start

    @property
    def value(self) -> int:
        return self._counter

    def tick(self) -> Clock:
        """Advance and return the next clock to stamp on a local op."""
        self._counter += 1
        return {"c": self._counter, "r": self.replica_id}

    def observe(self, clock: Clock) -> None:
        """Advance past an observed clock (Lamport receive rule)."""
        if clock["c"] > self._counter:
            self._counter = clock["c"]


def derive_replica_id(author_pub_hex: str, session_nonce: str) -> str:
    """Stable, unique-per-session replica id from author key + session nonce."""
    return f"{author_pub_hex}:{session_nonce}"
