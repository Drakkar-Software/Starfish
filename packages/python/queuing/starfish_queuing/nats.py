"""NATS queue implementation."""

import asyncio
import logging
from dataclasses import dataclass

import nats
from nats.aio.client import Client as NatsClient

from starfish_queuing.base import AbstractQueue

logger = logging.getLogger(__name__)


@dataclass
class NatsQueueOptions:
    """Connection options for :class:`NatsQueue`."""

    servers: str | list[str] = "nats://localhost:4222"
    """NATS server URL(s)."""

    name: str | None = None
    """Optional client name (visible in NATS monitoring)."""


class NatsQueue(AbstractQueue):
    """Publish messages to a NATS server.

    Connects lazily on the first :meth:`publish` call if :meth:`connect` has
    not been called explicitly.  Use the explicit lifecycle for best control::

        queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))
        await queue.connect()
        # … use queue …
        await queue.close()
    """

    def __init__(self, opts: NatsQueueOptions | None = None) -> None:
        self._opts = opts or NatsQueueOptions()
        self._nc: NatsClient | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            if self._nc is not None and self._nc.is_connected:
                return
            self._nc = await nats.connect(
                servers=self._opts.servers,
                name=self._opts.name,
            )

    async def _ensure_connected(self) -> NatsClient:
        if self._nc is None or not self._nc.is_connected:
            await self.connect()
        assert self._nc is not None  # noqa: S101
        return self._nc

    async def publish(self, subject: str, payload: bytes) -> None:
        nc = await self._ensure_connected()
        await nc.publish(subject, payload)

    async def close(self) -> None:
        async with self._lock:
            if self._nc is not None and self._nc.is_connected:
                await self._nc.close()
                self._nc = None
