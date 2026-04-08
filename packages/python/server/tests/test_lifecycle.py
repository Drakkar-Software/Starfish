"""Tests for graceful shutdown."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from starfish_server.lifecycle import GracefulShutdown, GracefulShutdownOptions


@pytest.mark.asyncio
async def test_shutdown_calls_on_shutdown():
    callback = AsyncMock()
    gs = GracefulShutdown(GracefulShutdownOptions(on_shutdown=callback, signals=[]))
    await gs.shutdown()
    callback.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_stops_replica_manager():
    rm = AsyncMock()
    rm.stop = AsyncMock()
    gs = GracefulShutdown(GracefulShutdownOptions(replica_manager=rm, signals=[]))
    await gs.shutdown()
    rm.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_closes_queue():
    queue = AsyncMock()
    queue.close = AsyncMock()
    gs = GracefulShutdown(GracefulShutdownOptions(queue=queue, signals=[]))
    await gs.shutdown()
    queue.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_idempotent():
    callback = AsyncMock()
    gs = GracefulShutdown(GracefulShutdownOptions(on_shutdown=callback, signals=[]))
    await gs.shutdown()
    await gs.shutdown()
    callback.assert_awaited_once()
