"""The queuing plugin's shutdown hook closes the queue during graceful shutdown."""

import pytest
from unittest.mock import AsyncMock

from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions
from starfish_queuing import create_queuing_server_plugin
from starfish_queuing.base import AbstractQueue


class _SpyQueue(AbstractQueue):
    def __init__(self) -> None:
        self.close_calls = 0

    async def publish(self, subject: str, payload: bytes) -> None:  # pragma: no cover
        pass

    async def close(self) -> None:
        self.close_calls += 1


@pytest.mark.asyncio
async def test_graceful_shutdown_invokes_plugin_shutdown_closing_queue():
    queue = _SpyQueue()
    plugin = create_queuing_server_plugin(queue=queue, collections={})

    gs = GracefulShutdown(GracefulShutdownOptions(plugins=[plugin], signals=[]))
    await gs.shutdown()

    assert queue.close_calls == 1


@pytest.mark.asyncio
async def test_plugin_shutdown_hook_calls_queue_close():
    queue = AsyncMock(spec=AbstractQueue)
    plugin = create_queuing_server_plugin(queue=queue, collections={})

    assert plugin.shutdown is not None
    await plugin.shutdown()
    queue.close.assert_awaited_once()
