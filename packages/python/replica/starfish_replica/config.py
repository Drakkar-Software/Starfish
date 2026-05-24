"""Replica configuration types. Owned by the replica plugin — apps pass a
``{ collection_name: RemoteConfig }`` map to ``create_replica_server_plugin``.

(Moved out of ``starfish-server``'s ``CollectionConfig`` so the core schema no
longer knows about replication — mirrors how ``QueueConfig`` lives in
``starfish-queuing``.)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, Field


class WriteMode(StrEnum):
    """Controls how local client writes are handled on a replica collection."""

    PULL_ONLY = "pull_only"
    """Only the ReplicaManager writes locally; local client pushes are rejected (405)."""

    PUSH_THROUGH = "push_through"
    """Local client pushes are forwarded to the primary; the replica syncs back afterwards."""

    BIDIRECTIONAL = "bidirectional"
    """Local client pushes are stored locally and merged (remote-wins) with the primary on sync."""

    PUSH_ONLY = "push_only"
    """Local client pushes are stored locally; pull requests are rejected (405).
    The replica does not sync from the primary — data is managed entirely locally."""


class SyncTrigger(StrEnum):
    """Events that trigger a sync from the primary."""

    SCHEDULED = "scheduled"
    """Sync on a fixed interval (``interval_ms``)."""

    ON_PULL = "on_pull"
    """Sync before serving each local ``GET /pull/…`` request (lazy / always-fresh)."""


class RemoteConfig(BaseModel):
    """Declares that a collection should be replicated from a remote (primary) starfish server."""

    model_config = {"populate_by_name": True}

    url: str
    """Base URL of the primary starfish server, e.g. ``https://primary.example.com/v1``."""

    pull_path: str = Field(alias="pullPath")
    """Pull endpoint path on the primary, e.g. ``/pull/posts/featured``.
    Must be a static path — no template variables."""

    push_path: str | None = Field(default=None, alias="pushPath")
    """Push endpoint path on the primary. Required for ``push_through`` and ``bidirectional`` write modes."""

    interval_ms: int = Field(default=60_000, gt=0, alias="intervalMs")
    """Sync interval in milliseconds (used by the ``scheduled`` trigger). Defaults to 60 000 ms."""

    headers: dict[str, str] = Field(default_factory=dict)
    """Static HTTP headers sent to the primary on every request (e.g. ``Authorization: Bearer <token>``).
    These credentials must satisfy the primary collection's ``readRoles`` (and ``writeRoles`` for write-through)."""

    write_mode: WriteMode = Field(default=WriteMode.PULL_ONLY, alias="writeMode")
    """How local client writes are handled. Defaults to ``pull_only``."""

    sync_triggers: list[SyncTrigger] = Field(
        default_factory=lambda: [SyncTrigger.SCHEDULED],
        alias="syncTriggers",
    )
    """Which events trigger a sync from the primary. Defaults to ``[scheduled]``."""

    on_pull_min_interval_ms: int | None = Field(default=None, gt=0, alias="onPullMinIntervalMs")
    """Minimum time in milliseconds between two consecutive syncs triggered by ``on_pull``.

    When a client pulls and this cooldown has not elapsed since the last sync, the replica
    skips the round-trip to the primary and serves the locally cached data instead.

    ``None`` (default) means every ``on_pull`` request always syncs from the primary.
    Only relevant when ``on_pull`` is listed in ``sync_triggers``."""


@dataclass
class RemoteCollection:
    """A collection to replicate: the manager needs its name (route key), its
    static storage path (document key), and its :class:`RemoteConfig`."""

    name: str
    storage_path: str
    remote: RemoteConfig
