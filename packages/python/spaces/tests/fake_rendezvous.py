"""An in-memory rendezvous server with the real CAS semantics.

Shared by the join-request tests. Models the two behaviors the security
properties actually depend on:

- an UNWRITTEN slot pulls as an empty document with a sentinel hash (not a 404),
  which is what makes ``clear_space_join_grant`` work on a never-written slot;
- ``base_hash=None`` means **create-only** — it succeeds only while the slot is
  still unwritten, and 409s against an occupied one rather than overwriting it.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from starfish_sdk.types import ConflictError

EMPTY_HASH = "empty-hash"
"""What the server reports for a slot nothing has been published to yet."""


class _Res:
    def __init__(self, data: Any, hash_: Optional[str]) -> None:
        self.data = data
        self.hash = hash_


class FakeRendezvous:
    """A single-namespace public rendezvous collection."""

    def __init__(self) -> None:
        self.docs: dict[str, tuple[dict[str, Any], str]] = {}
        self.push_calls = 0
        self._seq = 0

    # ── helpers for tests ─────────────────────────────────────────────────────

    @staticmethod
    def key_of(path: str) -> str:
        """Strip the ``/pull/`` or ``/push/`` prefix to get the storage key."""
        for prefix in ("/pull/", "/push/"):
            if path.startswith(prefix):
                return path[len(prefix) :]
        return path

    def raw(self, key: str) -> Optional[dict[str, Any]]:
        entry = self.docs.get(key)
        return entry[0] if entry else None

    def hash_of(self, key: str) -> str:
        entry = self.docs.get(key)
        return entry[1] if entry else EMPTY_HASH

    def force_write(self, key: str, data: dict[str, Any]) -> str:
        """Write bypassing CAS — simulates a third party occupying the slot."""
        self._seq += 1
        h = f"h{self._seq}"
        self.docs[key] = (dict(data), h)
        return h

    # ── client surface ────────────────────────────────────────────────────────

    async def pull(self, path: str) -> _Res:
        key = self.key_of(path)
        entry = self.docs.get(key)
        if entry is None:
            # Matches the deployed behavior: an unwritten doc is an empty
            # payload with a real hash, NOT a 404.
            return _Res({}, EMPTY_HASH)
        return _Res(json.loads(json.dumps(entry[0])), entry[1])

    async def push(
        self, path: str, data: dict[str, Any], base_hash: Optional[str]
    ) -> _Res:
        self.push_calls += 1
        key = self.key_of(path)
        occupied = key in self.docs
        if base_hash is None:
            # Create-only: the slot must still be genuinely fresh.
            if occupied:
                raise ConflictError("slot already occupied (create-only push)")
        elif base_hash != self.hash_of(key):
            raise ConflictError("hash_mismatch")
        self._seq += 1
        new_hash = f"h{self._seq}"
        self.docs[key] = (json.loads(json.dumps(data)), new_hash)
        return _Res(data, new_hash)


class AlwaysConflictRendezvous(FakeRendezvous):
    """Every push 409s — for the clear-retry-exhaustion path."""

    async def push(self, path: str, data: dict[str, Any], base_hash: Optional[str]) -> _Res:
        self.push_calls += 1
        raise ConflictError("hash_mismatch")
