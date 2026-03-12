"""Replica manager — scheduled and on-demand sync from a remote primary starfish."""


import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from starfish_server.config.schema import CollectionConfig, SyncTrigger, WriteMode

from starfish_server.interfaces import IObjectStore
from starfish_protocol.merge import deep_merge
from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess

logger = logging.getLogger(__name__)



class ReplicaManager:
    """Manages replication from remote (primary) starfish servers.

    For each collection with a ``remote`` config, syncs data from the primary to
    local storage. Write mode, sync triggers, and interval are driven by config.
    """

    def __init__(
        self,
        store: IObjectStore,
        collections: list[CollectionConfig],
        *,
        self_base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        on_error: Callable[[str, Exception], None] | None = None,
    ) -> None:
        self._store = store
        self._remote_cols = [c for c in collections if c.remote is not None]
        self._self_base_url = self_base_url
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._on_error = on_error or (
            lambda name, exc: logger.error("[ReplicaManager] %s: %s", name, exc)
        )
        self._last_hash: dict[str, str] = {}
        self._last_sync_at: dict[str, float] = {}
        self._tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        """Start background sync tasks and subscribe to primaries (webhook trigger)."""
        for col in self._remote_cols:
            remote = col.remote  # type: ignore[assignment]  # filtered above

            if SyncTrigger.WEBHOOK in remote.sync_triggers and self._self_base_url:
                asyncio.create_task(self._subscribe(col))

            if SyncTrigger.SCHEDULED in remote.sync_triggers:
                task = asyncio.create_task(self._run_loop(col))
                self._tasks.append(task)
            else:
                asyncio.create_task(self._sync_safe(col))

    async def stop(self) -> None:
        """Cancel all background tasks and close the HTTP client (if owned)."""
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self._owned_client:
            await self._client.aclose()

    async def on_notification(self, collection_name: str) -> None:
        """Called by ``POST /replica/notify`` when the primary signals a write."""
        col = self._find(collection_name)
        if col is None:
            logger.warning("[ReplicaManager] Notification for unknown collection %r", collection_name)
            return
        await self._sync_safe(col)

    async def on_pull(self, collection_name: str) -> None:
        """Called by the pull route when ``on_pull`` is listed in ``sync_triggers``.

        Awaited before the local store is read, ensuring the response is fresh.
        If ``on_pull_min_interval_ms`` is configured and the last sync occurred within
        that window, the primary is not contacted and cached local data is served instead.
        """
        col = self._find(collection_name)
        if col is None:
            return

        min_interval_ms = col.remote.on_pull_min_interval_ms if col.remote else None  # type: ignore[union-attr]
        if min_interval_ms is not None:
            last = self._last_sync_at.get(collection_name)
            if last is not None and (time.monotonic() - last) * 1000 < min_interval_ms:
                return  # within cooldown — serve cached local data

        await self._sync_safe(col)

    async def sync_now(self, name: str) -> None:
        """Trigger an immediate sync for a single collection by name."""
        col = self._find(name)
        if col is None:
            raise ValueError(f"[ReplicaManager] Unknown remote collection: {name!r}")
        await self._do_sync(col)

    async def sync_all(self) -> None:
        """Trigger an immediate sync for all remote collections in parallel."""
        await asyncio.gather(*(self._sync_safe(col) for col in self._remote_cols))

    def _find(self, name: str) -> CollectionConfig | None:
        return next((c for c in self._remote_cols if c.name == name), None)

    async def _run_loop(self, col: CollectionConfig) -> None:
        interval = col.remote.interval_ms / 1000  # type: ignore[union-attr]
        while True:
            await self._sync_safe(col)
            await asyncio.sleep(interval)

    async def _sync_safe(self, col: CollectionConfig) -> None:
        try:
            await self._do_sync(col)
        except Exception as exc:  # noqa: BLE001
            self._on_error(col.name, exc)

    async def _do_sync(self, col: CollectionConfig) -> None:
        remote = col.remote  # type: ignore[assignment]

        if remote.write_mode == WriteMode.PUSH_ONLY:
            return

        document_key = col.storage_path

        primary_url = f"{remote.url.rstrip('/')}{remote.pull_path}"
        resp = await self._client.get(
            primary_url,
            headers={"Accept": "application/json", **remote.headers},
        )
        resp.raise_for_status()
        pulled: dict[str, Any] = resp.json()

        primary_hash: str = pulled.get("hash", "")
        primary_data: dict[str, Any] = pulled.get("data", {})

        if not primary_hash:
            return

        if self._last_hash.get(col.name) == primary_hash:
            return

        raw_local = await self._store.get_string(document_key)
        current_local_hash: str = ""
        current_local_data: dict[str, Any] = {}
        if raw_local:
            import json
            local_doc = json.loads(raw_local)
            current_local_hash = local_doc.get("hash", "")
            current_local_data = local_doc.get("data", {})

        if current_local_hash == primary_hash:
            self._last_hash[col.name] = primary_hash
            return

        if remote.write_mode == WriteMode.BIDIRECTIONAL and current_local_data:
            data_to_write = deep_merge(current_local_data, primary_data)
        else:
            data_to_write = primary_data

        base_hash = current_local_hash if current_local_hash else None
        result = await push(self._store, document_key, data_to_write, base_hash)

        if not isinstance(result, PushSuccess):
            raise RuntimeError(
                f"[ReplicaManager] Concurrent write on {col.name!r} — will retry"
            )

        self._last_hash[col.name] = result.hash
        self._last_sync_at[col.name] = time.monotonic()
        logger.debug("[ReplicaManager] Synced %r (hash=%s)", col.name, result.hash)

    async def _subscribe(self, col: CollectionConfig) -> None:
        """Register this replica's webhook URL with the primary."""
        remote = col.remote  # type: ignore[assignment]
        webhook_url = self._self_base_url
        subscribe_url = f"{remote.url.rstrip('/')}/replica/subscribe"
        try:
            resp = await self._client.post(
                subscribe_url,
                json={"webhook_url": webhook_url, "collections": [col.name]},
                headers={"Content-Type": "application/json", **remote.headers},
            )
            if not resp.is_success:
                logger.warning(
                    "[ReplicaManager] Subscription to %s returned HTTP %s",
                    subscribe_url,
                    resp.status_code,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "[ReplicaManager] Could not subscribe to %s: %s (scheduled pulls will still work)",
                subscribe_url,
                exc,
            )
