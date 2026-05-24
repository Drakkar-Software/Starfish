"""Replica manager — scheduled and on-demand sync from a remote primary starfish."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from starfish_protocol.merge import deep_merge
from starfish_server.protocol.push import push
from starfish_server.router.helpers import deep_sanitize
from starfish_server.protocol.types import PushSuccess
from starfish_server.storage.base import AbstractObjectStore

from starfish_replica.config import RemoteCollection, RemoteConfig, SyncTrigger, WriteMode

logger = logging.getLogger(__name__)


class ReplicaManager:
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
        self._store = store
        self._remote_cols = list(collections)
        self._owned_client = client is None
        self._client = client or httpx.AsyncClient(timeout=30.0)
        self._on_error = on_error or (
            lambda name, exc: logger.error("[ReplicaManager] %s: %s", name, exc)
        )
        self._last_hash: dict[str, str] = {}
        self._last_sync_at: dict[str, float] = {}
        self._tasks: list[asyncio.Task[None]] = []

    def remote_for(self, name: str) -> RemoteConfig | None:
        """The :class:`RemoteConfig` for a collection name, or ``None`` if not replicated."""
        col = self._find(name)
        return col.remote if col else None

    async def start(self) -> None:
        """Start background sync tasks for all remote collections."""
        for col in self._remote_cols:
            remote = col.remote

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

    async def on_pull(self, collection_name: str) -> None:
        """Called by the pull route when ``on_pull`` is listed in ``sync_triggers``.

        Awaited before the local store is read, ensuring the response is fresh.
        If ``on_pull_min_interval_ms`` is configured and the last sync occurred within
        that window, the primary is not contacted and cached local data is served instead.
        """
        col = self._find(collection_name)
        if col is None:
            return

        min_interval_ms = col.remote.on_pull_min_interval_ms
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

    async def proxy_push(self, name: str, raw_body: bytes | str) -> tuple[int, Any]:
        """Forward a client push to the primary (write_mode ``push_through``).

        Returns ``(status, body)`` to relay to the client. On success, triggers
        a background sync so the local replica catches up. Framework-neutral —
        the caller (replica plugin) turns this into an HTTP response.
        """
        col = self._find(name)
        if col is None:
            return 404, {"error": f"Unknown remote collection: {name!r}"}
        remote = col.remote
        primary_url = f"{remote.url.rstrip('/')}{remote.push_path}"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **remote.headers,
        }

        try:
            resp = await self._client.post(primary_url, content=raw_body, headers=headers)
        except httpx.HTTPError as exc:
            logger.error("Failed to reach primary for %r: %s", name, exc)
            return 502, {"error": "Failed to reach primary"}

        if resp.status_code == 409:
            return 409, {"error": "hash_mismatch"}
        if not resp.is_success:
            return resp.status_code, {"error": f"Primary returned {resp.status_code}"}

        body = resp.json()

        # Validate the primary's response shape before relaying it to our client.
        # A successful push returns ``{ hash, timestamp }``; refuse to forward an
        # arbitrary/garbage body a compromised or misbehaving primary might send.
        if not isinstance(body, dict) or not isinstance(body.get("hash"), str):
            logger.error("Primary returned an unexpected push response shape for %r", name)
            return 502, {"error": "Primary returned an unexpected response"}

        # Trigger sync in background (don't await)
        task = asyncio.create_task(self.sync_now(name))
        task.add_done_callback(
            lambda t: logger.error("replica sync_now failed for %r: %s", name, t.exception())
            if not t.cancelled() and t.exception() is not None
            else None
        )

        return resp.status_code, body

    def _find(self, name: str) -> RemoteCollection | None:
        return next((c for c in self._remote_cols if c.name == name), None)

    async def _run_loop(self, col: RemoteCollection) -> None:
        interval = col.remote.interval_ms / 1000
        while True:
            await self._sync_safe(col)
            await asyncio.sleep(interval)

    async def _sync_safe(self, col: RemoteCollection) -> None:
        try:
            await self._do_sync(col)
        except Exception as exc:  # noqa: BLE001
            self._on_error(col.name, exc)

    async def _do_sync(self, col: RemoteCollection) -> None:
        remote = col.remote

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
            try:
                local_doc = json.loads(raw_local)
                current_local_hash = local_doc.get("hash", "")
                current_local_data = local_doc.get("data", {})
            except json.JSONDecodeError as exc:
                logger.error(
                    "[ReplicaManager] Corrupt local document at %r — treating as empty: %s",
                    document_key, exc,
                )
                # current_local_hash stays "" — push with baseHash="" will overwrite

        if current_local_hash == primary_hash:
            self._last_hash[col.name] = primary_hash
            return

        if remote.write_mode == WriteMode.BIDIRECTIONAL and current_local_data:
            data_to_write = deep_merge(current_local_data, primary_data)
        else:
            data_to_write = primary_data

        # Strip prototype-pollution keys before writing primary data into the
        # local store. The bidirectional merge drops them via deep_merge, but the
        # pull-only / push-through path writes the primary's ``data`` verbatim and
        # must not trust it — a compromised primary could otherwise plant a
        # ``__proto__`` / ``__class__`` payload.
        sanitized = deep_sanitize(data_to_write)

        # Use current_local_hash directly ("" works for both "no document" and
        # "corrupt document"): push() treats base_hash="" the same as no hash when
        # the stored current_hash is also "". Must NOT coerce "" → None — push()
        # rejects base_hash=None when a (corrupt) doc is present, which would leave
        # a corrupt local doc permanently unrecoverable (sync would raise
        # "Concurrent write" forever). A valid local doc still yields its real
        # hash, so genuine concurrent-write detection is preserved.
        base_hash = current_local_hash
        result = await push(self._store, document_key, sanitized, base_hash)

        if not isinstance(result, PushSuccess):
            raise RuntimeError(
                f"[ReplicaManager] Concurrent write on {col.name!r} — will retry"
            )

        self._last_hash[col.name] = result.hash
        self._last_sync_at[col.name] = time.monotonic()
        logger.debug("[ReplicaManager] Synced %r (hash=%s)", col.name, result.hash)
