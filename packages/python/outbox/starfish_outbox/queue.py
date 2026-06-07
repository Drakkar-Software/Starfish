"""A durable, per-identity offline **write-queue** — the client-side complement to
the server-side ``queuing`` extension. It queues opaque items and the caller owns *what*
a queued item is and *how* it is sent.

Invariants:

- **Dedup by id.** ``enqueue(id, …)`` ignores an id already queued.
- **Removed only on confirmed success** (see :func:`drain_outbox`).
- **Persisted per identity.** Write-through to a :class:`LocalCache` under the key
  bound by :meth:`OutboxQueue.hydrate` — so mutating methods are ``async``.
- **Crash-safe claim.** A stuck ``sending`` entry resets to ``queued`` on the next
  ``hydrate``; ``claim`` is single-shot so concurrent drains never double-send.

JSON-compatible on disk with the TypeScript ``@drakkar.software/starfish-outbox``
(entry keys ``id`` / ``item`` / ``status`` / ``attempts`` / ``enqueuedAt``).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, Optional, Protocol, TypeVar

T = TypeVar("T")

OutboxStatus = str  # "queued" | "sending" | "failed"


class LocalCache(Protocol):
    """Minimal async key/value cache (localStorage / AsyncStorage wrapper)."""

    async def get_item(self, key: str) -> Optional[str]: ...
    async def set_item(self, key: str, value: str) -> None: ...
    async def remove_item(self, key: str) -> None: ...


@dataclass
class OutboxEntry(Generic[T]):
    """One queued write: the caller's opaque ``item`` plus queue bookkeeping."""

    id: str
    item: T
    status: OutboxStatus
    attempts: int
    enqueued_at: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "item": self.item,
            "status": self.status,
            "attempts": self.attempts,
            "enqueuedAt": self.enqueued_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "OutboxEntry[Any]":
        return cls(
            id=d["id"],
            item=d["item"],
            status=d.get("status", "queued"),
            attempts=int(d.get("attempts", 0)),
            enqueued_at=int(d.get("enqueuedAt", 0)),
        )


def reset_sending_to_queued(items: list[OutboxEntry[T]]) -> list[OutboxEntry[T]]:
    """Reset entries stuck ``sending`` (claimed but never resolved) to ``queued``."""
    for it in items:
        if it.status == "sending":
            it.status = "queued"
    return items


class OutboxQueue(Generic[T]):
    """See module docstring. Mutators are ``async`` because each writes through to
    the cache; ``get`` / ``pending`` / ``subscribe`` are synchronous."""

    def __init__(self, cache: LocalCache) -> None:
        self._cache = cache
        self._items: list[OutboxEntry[T]] = []
        self._cache_key: Optional[str] = None
        self._listeners: set[Callable[[], None]] = set()

    def get(self) -> list[OutboxEntry[T]]:
        return self._items

    def subscribe(self, listener: Callable[[], None]) -> Callable[[], None]:
        self._listeners.add(listener)
        return lambda: self._listeners.discard(listener)

    def _notify(self) -> None:
        for listener in list(self._listeners):
            listener()

    async def _commit(self, items: list[OutboxEntry[T]]) -> None:
        self._items = items
        if self._cache_key is not None:
            try:
                await self._cache.set_item(self._cache_key, json.dumps([e.to_dict() for e in items]))
            except Exception:
                pass
        self._notify()

    async def hydrate(self, cache_key: str) -> None:
        self._cache_key = cache_key
        loaded: list[OutboxEntry[T]] = []
        try:
            raw = await self._cache.get_item(cache_key)
            if raw:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    loaded = [OutboxEntry.from_dict(d) for d in parsed]
        except Exception:
            loaded = []
        self._items = reset_sending_to_queued(loaded)
        self._notify()

    def clear(self) -> None:
        self._cache_key = None
        self._items = []
        self._notify()

    async def enqueue(self, id: str, item: T, ts: Optional[int] = None) -> None:
        if any(i.id == id for i in self._items):
            return  # dedup by id
        entry = OutboxEntry(id=id, item=item, status="queued", attempts=0, enqueued_at=ts or int(time.time() * 1000))
        await self._commit([*self._items, entry])

    async def claim(self, id: str) -> bool:
        it = next((i for i in self._items if i.id == id), None)
        if it is None or it.status == "sending":
            return False
        await self._commit([
            (OutboxEntry(i.id, i.item, "sending", i.attempts, i.enqueued_at) if i.id == id else i)
            for i in self._items
        ])
        return True

    async def remove(self, id: str) -> None:
        await self._commit([i for i in self._items if i.id != id])

    async def record_failure(self, id: str, max_attempts: int) -> None:
        def updated(i: OutboxEntry[T]) -> OutboxEntry[T]:
            if i.id != id:
                return i
            attempts = i.attempts + 1
            status = "failed" if attempts >= max_attempts else "queued"
            return OutboxEntry(i.id, i.item, status, attempts, i.enqueued_at)

        await self._commit([updated(i) for i in self._items])

    async def mark_failed(self, id: str) -> None:
        await self._commit([
            (OutboxEntry(i.id, i.item, "failed", i.attempts + 1, i.enqueued_at) if i.id == id else i)
            for i in self._items
        ])

    async def retry(self, id: str) -> None:
        await self._commit([
            (OutboxEntry(i.id, i.item, "queued", i.attempts, i.enqueued_at) if i.id == id else i)
            for i in self._items
        ])

    def pending(self, predicate: Optional[Callable[[T], bool]] = None) -> list[OutboxEntry[T]]:
        return [i for i in self._items if (predicate(i.item) if predicate else True)]
