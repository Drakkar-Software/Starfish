"""Pydantic models for sync configuration."""


from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from starfish_server.constants import ENCRYPTION_NONE, ENCRYPTION_IDENTITY, ENCRYPTION_SERVER, ENCRYPTION_DELEGATED

EncryptionMode = Literal["none", "identity", "server", "delegated"]


class WriteMode(str, Enum):
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


class SyncTrigger(str, Enum):
    """Events that trigger a sync from the primary."""

    SCHEDULED = "scheduled"
    """Sync on a fixed interval (``interval_ms``)."""

    WEBHOOK = "webhook"
    """Sync when the primary sends a ``POST /replica/notify`` notification."""

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

    webhook_secret: str | None = Field(default=None, alias="webhookSecret")
    """HMAC-SHA256 secret used to verify incoming ``POST /replica/notify`` requests.
    Required when ``webhook`` is listed in ``sync_triggers``."""

    on_pull_min_interval_ms: int | None = Field(default=None, gt=0, alias="onPullMinIntervalMs")
    """Minimum time in milliseconds between two consecutive syncs triggered by ``on_pull``.

    When a client pulls and this cooldown has not elapsed since the last sync, the replica
    skips the round-trip to the primary and serves the locally cached data instead.

    ``None`` (default) means every ``on_pull`` request always syncs from the primary.
    Only relevant when ``on_pull`` is listed in ``sync_triggers``."""


class CollectionConfig(BaseModel):
    """Configuration for a single synced collection."""

    model_config = {"populate_by_name": True}

    name: str = Field(min_length=1)
    storage_path: str = Field(min_length=1, alias="storagePath")
    read_roles: list[str] = Field(alias="readRoles")
    write_roles: list[str] = Field(alias="writeRoles")
    encryption: EncryptionMode
    max_body_bytes: int = Field(gt=0, alias="maxBodyBytes")
    rate_limit: bool | None = Field(default=None, alias="rateLimit")
    pull_only: bool | None = Field(default=None, alias="pullOnly")
    push_only: bool | None = Field(default=None, alias="pushOnly")
    force_full_fetch: bool | None = Field(default=None, alias="forceFullFetch")
    client_encrypted: bool | None = Field(default=None, alias="clientEncrypted")
    bundle: str | None = Field(default=None, min_length=1)
    remote: RemoteConfig | None = Field(default=None)
    """When set, this collection is replicated from a remote primary starfish server.
    All replica behavior (write mode, sync triggers, interval, auth) is fully described here."""


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    model_config = {"populate_by_name": True}

    window_ms: int = Field(gt=0, alias="windowMs")
    max_requests: int = Field(gt=0, alias="maxRequests")


class SyncConfig(BaseModel):
    """Top-level sync configuration."""

    model_config = {"populate_by_name": True}

    version: Literal[1]
    collections: list[CollectionConfig]
    rate_limit: RateLimitConfig | None = Field(default=None, alias="rateLimit")
