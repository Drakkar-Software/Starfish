"""Durable write-queue: dedup, persistence + crash-safe hydrate, single-shot claim,
drain success/failure with auto-retry-then-fail, predicate filtering."""

from __future__ import annotations

import json
from typing import Optional

from starfish_outbox import OutboxQueue, drain_outbox


class MemCache:
    def __init__(self) -> None:
        self.map: dict[str, str] = {}

    async def get_item(self, key: str) -> Optional[str]:
        return self.map.get(key)

    async def set_item(self, key: str, value: str) -> None:
        self.map[key] = value

    async def remove_item(self, key: str) -> None:
        self.map.pop(key, None)


async def test_enqueue_dedup_and_persist() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"room": "r1", "text": "hi"})
    await q.enqueue("m1", {"room": "r1", "text": "dup"})  # ignored
    await q.enqueue("m2", {"room": "r2", "text": "yo"})
    assert [e.id for e in q.get()] == ["m1", "m2"]
    persisted = json.loads(cache.map["outbox.me"])
    assert len(persisted) == 2
    assert persisted[0]["item"]["text"] == "hi"
    assert "enqueuedAt" in persisted[0]


async def test_reset_sending_on_hydrate() -> None:
    cache = MemCache()
    cache.map["outbox.me"] = json.dumps(
        [{"id": "m1", "item": {"text": "x"}, "status": "sending", "attempts": 1, "enqueuedAt": 1}]
    )
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    assert q.get()[0].status == "queued"


async def test_claim_single_shot() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"text": "x"})
    assert await q.claim("m1") is True
    assert await q.claim("m1") is False


async def test_drain_sends_oldest_first_and_removes() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"text": "a"})
    await q.enqueue("m2", {"text": "b"})
    order: list[str] = []

    async def send(entry):
        order.append(entry.item["text"])

    res = await drain_outbox(q, send)
    assert order == ["a", "b"]
    assert (res.sent, res.failed) == (2, 0)
    assert q.get() == []


async def test_auto_retry_then_failed() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"text": "x"})

    async def send(_entry):
        raise RuntimeError("offline")

    r1 = await drain_outbox(q, send, max_attempts=2)
    assert (r1.sent, r1.failed) == (0, 0)
    assert q.get()[0].status == "queued" and q.get()[0].attempts == 1
    r2 = await drain_outbox(q, send, max_attempts=2)
    assert (r2.sent, r2.failed) == (0, 1)
    assert q.get()[0].status == "failed"


async def test_failed_skipped_until_retry() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"text": "x"})

    async def fail(_e):
        raise RuntimeError("x")

    await drain_outbox(q, fail, max_attempts=1)
    assert q.get()[0].status == "failed"

    async def ok(_e):
        return None

    r1 = await drain_outbox(q, ok)
    assert r1.sent == 0
    await q.retry("m1")
    r2 = await drain_outbox(q, ok)
    assert r2.sent == 1


async def test_pending_predicate() -> None:
    cache = MemCache()
    q: OutboxQueue = OutboxQueue(cache)
    await q.hydrate("outbox.me")
    await q.enqueue("m1", {"room": "r1"})
    await q.enqueue("m2", {"room": "r2"})
    await q.enqueue("m3", {"room": "r1"})
    assert [e.id for e in q.pending(lambda m: m["room"] == "r1")] == ["m1", "m3"]
