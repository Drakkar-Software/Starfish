"""Tests for in-memory and callback-based queue implementations."""

import pytest

from starfish_server.queue.base import AbstractQueue
from starfish_server.queue.memory import MemoryQueue, CustomQueue


async def test_memory_queue_records_messages():
    q = MemoryQueue()
    await q.publish("posts", b'{"collection":"posts"}')
    await q.publish("settings", b'{"collection":"settings"}')

    assert len(q.messages) == 2
    assert q.messages[0] == ("posts", b'{"collection":"posts"}')
    assert q.messages[1] == ("settings", b'{"collection":"settings"}')


async def test_memory_queue_starts_empty():
    q = MemoryQueue()
    assert q.messages == []


async def test_custom_queue_sync_callback():
    received: list[tuple[str, bytes]] = []

    def on_publish(subject: str, payload: bytes) -> None:
        received.append((subject, payload))

    q = CustomQueue(on_publish=on_publish)
    await q.publish("topic", b"data")

    assert received == [("topic", b"data")]


async def test_custom_queue_async_callback():
    received: list[tuple[str, bytes]] = []

    async def on_publish(subject: str, payload: bytes) -> None:
        received.append((subject, payload))

    q = CustomQueue(on_publish=on_publish)
    await q.publish("topic", b"data")

    assert received == [("topic", b"data")]


async def test_custom_queue_no_callback_is_noop():
    q = CustomQueue()
    await q.publish("topic", b"data")  # should not raise


async def test_abstract_queue_connect_close_are_noops():
    """Default connect() and close() do nothing — safe to call."""
    q = MemoryQueue()
    await q.connect()
    await q.close()
