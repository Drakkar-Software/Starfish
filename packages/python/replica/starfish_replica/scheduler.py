"""``ChannelScheduler`` — the pure scheduling half of the old ``ReplicaManager``.

Interval loop, ``on_pull`` cooldown, and the ``on_error`` funnel, driving any
number of :class:`ScheduledChannel` entries. Deliberately depends on nothing
HTTP-specific — no import of ``http_channel`` or ``starfish_server`` anywhere
in this module (enforced by ``tests/test_no_server_import.py``) — so it can be
imported on a client with no server install, e.g. by ``starfish_replica.space``.

Mirrors the TS package's ``scheduler.ts``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from starfish_replica.channel import REPLICATOR_CTX, ScheduledChannel, SyncTrigger

logger = logging.getLogger(__name__)

__all__ = ["ChannelScheduler", "default_scheduler_on_error"]


def default_scheduler_on_error(name: str, exc: Exception) -> None:
    logger.error("[ChannelScheduler] %s: %s", name, exc)


class ChannelScheduler:
    """Drives a set of :class:`ScheduledChannel` entries on their configured
    triggers (``scheduled`` interval loop, ``on_pull`` lazy sync + cooldown)."""

    def __init__(
        self,
        entries: list[ScheduledChannel],
        *,
        on_error: Callable[[str, Exception], None] | None = None,
    ) -> None:
        self._entries = list(entries)
        self._on_error = on_error or default_scheduler_on_error
        self._last_sync_at: dict[str, float] = {}
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Start background sync tasks for all scheduled-trigger entries."""
        for entry in self._entries:
            if SyncTrigger.SCHEDULED in entry.schedule.triggers:
                task = asyncio.create_task(self._run_loop(entry))
                self._tasks.append(task)
            else:
                asyncio.create_task(self._sync_safe(entry))

    async def stop(self) -> None:
        """Cancel all background tasks."""
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def on_pull(self, name: str) -> None:
        """Called before serving a local pull when ``on_pull`` is one of the
        channel's triggers.

        If ``on_pull_min_interval_ms`` is configured and the last sync
        occurred within that window, the channel is not synced and cached
        local data is served instead.
        """
        entry = self._find(name)
        if entry is None:
            return

        min_interval_ms = entry.schedule.on_pull_min_interval_ms
        if min_interval_ms is not None:
            last = self._last_sync_at.get(name)
            if last is not None and (time.monotonic() - last) * 1000 < min_interval_ms:
                return  # within cooldown — serve cached local data

        await self._sync_safe(entry)

    async def sync_now(self, name: str) -> None:
        """Trigger an immediate sync for a single channel by name."""
        entry = self._find(name)
        if entry is None:
            raise ValueError(f"[ReplicaManager] Unknown remote collection: {name!r}")
        await self._do_sync(entry)

    async def sync_all(self) -> None:
        """Trigger an immediate sync for all channels in parallel."""
        await asyncio.gather(*(self._sync_safe(entry) for entry in self._entries))

    def _find(self, name: str) -> ScheduledChannel | None:
        return next((e for e in self._entries if e.channel.name == name), None)

    async def _run_loop(self, entry: ScheduledChannel) -> None:
        interval_ms = entry.schedule.interval_ms or 60_000
        interval = interval_ms / 1000
        while True:
            await self._sync_safe(entry)
            await asyncio.sleep(interval)

    async def _sync_safe(self, entry: ScheduledChannel) -> None:
        try:
            await self._do_sync(entry)
        except Exception as exc:  # noqa: BLE001
            self._on_error(entry.channel.name, exc)

    async def _do_sync(self, entry: ScheduledChannel) -> None:
        await entry.channel.sync(REPLICATOR_CTX)
        # Stamp on every COMPLETED sync (not just one that wrote something) — a
        # no-op sync (hash unchanged) still means we just checked the primary, so
        # the on_pull cooldown should apply to it too.
        self._last_sync_at[entry.channel.name] = time.monotonic()
