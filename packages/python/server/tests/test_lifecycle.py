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
async def test_shutdown_runs_plugin_shutdown_hooks():
    shutdown_hook = AsyncMock()
    plugin = MagicMock()
    plugin.shutdown = shutdown_hook
    gs = GracefulShutdown(GracefulShutdownOptions(plugins=[plugin], signals=[]))
    await gs.shutdown()
    shutdown_hook.assert_awaited_once()


@pytest.mark.asyncio
async def test_shutdown_idempotent():
    callback = AsyncMock()
    gs = GracefulShutdown(GracefulShutdownOptions(on_shutdown=callback, signals=[]))
    await gs.shutdown()
    await gs.shutdown()
    callback.assert_awaited_once()
