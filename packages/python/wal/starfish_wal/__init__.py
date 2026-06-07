"""starfish-wal — write-ahead-log / doc-diff collections with CRDT semantics.

This package ships the deterministic, cross-language CRDT core (clock + fold)
that mirrors ``@drakkar.software/starfish-wal`` and conforms to
``tests/test-vectors/wal-crdt.json``. The client document-log layer
(``WalDocument``: commit / materialize / snapshot) currently ships in the
TypeScript package; Python parity is planned.
"""

from starfish_wal.clock import (
    Clock,
    LamportClock,
    clock_greater,
    compare_clocks,
    derive_replica_id,
)
from starfish_wal.crdt import Op, WalCrdt

__all__ = [
    "Clock",
    "LamportClock",
    "clock_greater",
    "compare_clocks",
    "derive_replica_id",
    "Op",
    "WalCrdt",
]
