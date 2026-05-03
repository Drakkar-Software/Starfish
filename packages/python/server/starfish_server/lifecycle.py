"""Graceful shutdown utilities for Starfish servers."""


import asyncio
import logging
import signal
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Awaitable

if TYPE_CHECKING:
    from starfish_server.replica.manager import ReplicaManager
    from starfish_server.queue.base import AbstractQueue

logger = logging.getLogger(__name__)


@dataclass
class GracefulShutdownOptions:
    """Configuration for graceful shutdown."""
    on_shutdown: Callable[[], Awaitable[None]] | None = None
    timeout_s: float = 10.0
    replica_manager: "ReplicaManager | None" = None
    queue: "AbstractQueue | None" = None
    signals: list[signal.Signals] = field(
        default_factory=lambda: [signal.SIGTERM, signal.SIGINT],
    )


class GracefulShutdown:
    """Manages graceful shutdown of Starfish server resources.

    Usage::

        shutdown = GracefulShutdown(GracefulShutdownOptions(
            replica_manager=replica_mgr,
            queue=queue,
        ))
        shutdown.register()
        # ... run server ...
        shutdown.unregister()
    """

    def __init__(self, opts: GracefulShutdownOptions | None = None) -> None:
        self._opts = opts or GracefulShutdownOptions()
        self._shutting_down = False
        self._handlers: list[tuple[signal.Signals, Any]] = []

    async def shutdown(self) -> None:
        """Perform graceful shutdown of all managed resources."""
        if self._shutting_down:
            return
        self._shutting_down = True
        logger.info("Starfish graceful shutdown initiated")

        try:
            async with asyncio.timeout(self._opts.timeout_s):
                if self._opts.replica_manager:
                    await self._opts.replica_manager.stop()
                if self._opts.queue and hasattr(self._opts.queue, "close"):
                    await self._opts.queue.close()
                if self._opts.on_shutdown:
                    await self._opts.on_shutdown()
        except asyncio.TimeoutError:
            logger.error("Starfish graceful shutdown timed out after %.1fs", self._opts.timeout_s)
        except Exception:
            logger.exception("Error during Starfish graceful shutdown")

        logger.info("Starfish graceful shutdown complete")

    def register(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Register signal handlers for graceful shutdown."""
        _loop = loop or asyncio.get_event_loop()
        for sig in self._opts.signals:
            _loop.add_signal_handler(sig, lambda s=sig: asyncio.ensure_future(self.shutdown()))
            self._handlers.append((sig, None))

    def unregister(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Remove signal handlers."""
        _loop = loop or asyncio.get_event_loop()
        for sig, _ in self._handlers:
            try:
                _loop.remove_signal_handler(sig)
            except (ValueError, OSError):
                pass
        self._handlers.clear()
