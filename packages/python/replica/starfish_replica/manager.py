"""``ReplicaManager`` — back-compat HTTP-pull manager, now a thin subclass of
:class:`ChannelScheduler`.

Historically this module held both the scheduling logic (interval loop,
``on_pull`` cooldown, error funnel) and the HTTP-pull-into-``ObjectStore``
sync mechanics in one class. Those are now split out into
``scheduler.py`` (:class:`ChannelScheduler`, pure — no HTTP/server
dependency) and ``http_channel.py`` (:class:`HttpReplicaChannel`, the HTTP
mechanics). ``ReplicaManager`` keeps its original public constructor and
method surface — ``__init__(store, collections, ...)``, ``remote_for``,
``proxy_push``, ``stop`` — by building one :class:`HttpReplicaChannel` per
:class:`RemoteCollection` and delegating scheduling to the base class.

Mirrors the TS package's ``manager.ts``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

import httpx

from starfish_replica.channel import ChannelSchedule, ScheduledChannel
from starfish_replica.config import RemoteCollection, RemoteConfig
from starfish_replica.http_channel import HttpReplicaChannel
from starfish_replica.scheduler import ChannelScheduler
from starfish_server.storage.base import AbstractObjectStore

logger = logging.getLogger(__name__)

__all__ = ["ReplicaManager"]


def _schedule_from_remote(remote: RemoteConfig) -> ChannelSchedule:
    return ChannelSchedule(
        triggers=list(remote.sync_triggers),
        interval_ms=remote.interval_ms,
        on_pull_min_interval_ms=remote.on_pull_min_interval_ms,
    )


class ReplicaManager(ChannelScheduler):
    """Manages replication from remote (primary) starfish servers.

    For each :class:`RemoteCollection`, syncs data from the primary to local
    storage. Write mode, sync triggers, and interval are driven by config.
    """

    def __init__(
        self,
        store: AbstractObjectStore,
        collections: list[RemoteCollection],
        *,
        client: httpx.AsyncClient | None = None,
        on_error: Callable[[str, Exception], None] | None = None,
    ) -> None:
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(timeout=30.0)

        entries = [
            ScheduledChannel(
                channel=HttpReplicaChannel(store, col, self._client),
                schedule=_schedule_from_remote(col.remote),
            )
            for col in collections
        ]
        super().__init__(entries, on_error=on_error)

    async def stop(self) -> None:
        """Cancel all background tasks and close the HTTP client (if owned)."""
        await super().stop()
        if self._owned_client:
            await self._client.aclose()

    def remote_for(self, name: str) -> RemoteConfig | None:
        """The :class:`RemoteConfig` for a collection name, or ``None`` if not replicated."""
        entry = self._find(name)
        if entry is None or not isinstance(entry.channel, HttpReplicaChannel):
            return None
        return entry.channel.remote

    async def proxy_push(self, name: str, raw_body: bytes | str) -> tuple[int, Any]:
        """Forward a client push to the primary (write_mode ``push_through``).

        Returns ``(status, body)`` to relay to the client. On success, triggers
        a background sync so the local replica catches up. Framework-neutral —
        the caller (replica plugin) turns this into an HTTP response.
        """
        entry = self._find(name)
        if entry is None or not isinstance(entry.channel, HttpReplicaChannel):
            return 404, {"error": f"Unknown remote collection: {name!r}"}

        def on_success() -> None:
            task = asyncio.create_task(self.sync_now(name))
            task.add_done_callback(
                lambda t: logger.error("replica sync_now failed for %r: %s", name, t.exception())
                if not t.cancelled() and t.exception() is not None
                else None
            )

        return await entry.channel.proxy_push(raw_body, on_success=on_success)
