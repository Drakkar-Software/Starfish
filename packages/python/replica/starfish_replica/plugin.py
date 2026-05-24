"""Server plugin for the replication extension (Python mirror).

Implements the route hooks from the ``ServerPlugin`` contract:
- ``before_pull``: rejects pulls on write-only (``push_only``) collections, and
  triggers a sync from the primary when the ``on_pull`` trigger is configured.
- ``intercept_push``: rejects pushes on read-only (``pull_only``) collections,
  and proxies the push to the primary when the write mode is ``push_through``.
- ``shutdown``: stops the manager's background tasks.

Like ``starfish-queuing``, this plugin owns its config: apps pass a
``{ collection_name: RemoteConfig }`` map; the field is no longer part of the
core ``CollectionConfig``. The factory validates the config at construction and
raises on conflict.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

import httpx

from starfish_protocol.plugins import (
    PullHookContext,
    PullHookResult,
    PushHookContext,
    PushHookResult,
    ServerPlugin,
)
from starfish_server.config.schema import SyncConfig
from starfish_server.storage.base import AbstractObjectStore

from starfish_replica.config import RemoteCollection, RemoteConfig, SyncTrigger, WriteMode
from starfish_replica.manager import ReplicaManager
from starfish_replica.validate import validate_replica_config


@dataclass
class ReplicaServerPlugin:
    """Bundle returned by :func:`create_replica_server_plugin`.

    Pass ``.plugin`` to ``SyncRouterOptions(plugins=[...])`` and call
    ``await .manager.start()`` to begin scheduled/initial syncs.
    """

    plugin: ServerPlugin
    manager: ReplicaManager


def create_replica_server_plugin(
    *,
    store: AbstractObjectStore,
    sync_config: SyncConfig,
    collections: Mapping[str, RemoteConfig],
    client: httpx.AsyncClient | None = None,
    on_error: Callable[[str, Exception], None] | None = None,
) -> ReplicaServerPlugin:
    """Build a replica :class:`ServerPlugin` and its :class:`ReplicaManager`.

    Validates the config (cross-referencing *collections* against
    *sync_config*) and raises ``ValueError`` on conflict.
    """
    errors = validate_replica_config(sync_config, dict(collections))
    if errors:
        joined = "\n- ".join(errors)
        raise ValueError(f"[starfish-replica] invalid configuration:\n- {joined}")

    by_name = {c.name: c for c in sync_config.collections}
    remote_cols = [
        RemoteCollection(name=name, storage_path=by_name[name].storage_path, remote=remote)
        for name, remote in collections.items()
    ]

    manager = ReplicaManager(store, remote_cols, client=client, on_error=on_error)

    async def _before_pull(ctx: PullHookContext) -> PullHookResult:
        remote = manager.remote_for(ctx.collection)
        if remote is None:
            return PullHookResult(action="proceed")
        if remote.write_mode == WriteMode.PUSH_ONLY:
            return PullHookResult(
                action="reject", status=405, error="This collection is write-only on this server"
            )
        if SyncTrigger.ON_PULL in remote.sync_triggers:
            await manager.on_pull(ctx.collection)
        return PullHookResult(action="proceed")

    async def _intercept_push(ctx: PushHookContext) -> PushHookResult:
        remote = manager.remote_for(ctx.collection)
        if remote is None:
            return PushHookResult(action="proceed")
        if remote.write_mode == WriteMode.PULL_ONLY:
            return PushHookResult(
                action="reject", status=405, error="This collection is read-only on this server"
            )
        if remote.write_mode == WriteMode.PUSH_THROUGH:
            status, body = await manager.proxy_push(ctx.collection, ctx.raw_body)
            return PushHookResult(action="respond", status=status, body=body)
        # bidirectional / push_only → store locally, then sync reconciles
        return PushHookResult(action="proceed")

    async def _shutdown() -> None:
        await manager.stop()

    plugin = ServerPlugin(
        name="starfish-replica",
        before_pull=_before_pull,
        intercept_push=_intercept_push,
        shutdown=_shutdown,
    )
    return ReplicaServerPlugin(plugin=plugin, manager=manager)
