"""Pydantic models for sync configuration."""


from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from starfish_server.constants import ENCRYPTION_NONE, ENCRYPTION_IDENTITY, ENCRYPTION_SERVER, ENCRYPTION_DELEGATED

EncryptionMode = Literal["none", "identity", "server", "delegated"]


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


class QueueConfig(BaseModel):
    """Per-collection queue publishing configuration.

    When present on a :class:`CollectionConfig`, the server publishes a
    change event to the configured queue after every successful push.
    """

    model_config = {"populate_by_name": True}

    topic: str | None = Field(default=None)
    """NATS subject (or equivalent topic name) to publish to.

    Defaults to the collection ``name`` when ``None``."""

    include_params: bool = Field(default=False, alias="includeParams")
    """Include resolved path parameters (e.g. ``{"identity": "user-1"}``) in the
    published message payload."""

    include_body: bool = Field(default=False, alias="includeBody")
    """Include the full document data in the published message payload.

    Only applies to JSON collections — binary push events never include body.
    The ``body`` field contains the ``data`` from the push request body as sent
    by the client (before server-side sanitization of prototype-pollution keys)."""


class CollectionRateLimitConfig(BaseModel):
    """Per-collection rate limit overrides.

    Fields that are ``None`` fall back to the global ``rateLimit`` config.
    Passing an empty object (or ``"rateLimit": true`` in JSON) enables rate
    limiting with the global defaults.
    """

    model_config = {"populate_by_name": True}

    window_ms: int | None = Field(default=None, gt=0, alias="windowMs")
    """Override the global window (in milliseconds) for this collection."""

    max_requests: int | None = Field(default=None, gt=0, alias="maxRequests")
    """Override the global max requests per window for this collection."""


class FieldPermission(BaseModel):
    """Per-field access control within a collection document."""

    model_config = {"populate_by_name": True}

    read_roles: list[str] | None = Field(default=None, alias="readRoles")
    """Roles required to read this field.  ``None`` means no restriction."""

    write_roles: list[str] | None = Field(default=None, alias="writeRoles")
    """Roles required to write this field.  ``None`` means no restriction."""


class CollectionConfig(BaseModel):
    """Configuration for a single synced collection."""

    model_config = {"populate_by_name": True}

    name: str = Field(min_length=1)
    storage_path: str = Field(min_length=1, alias="storagePath")
    read_roles: list[str] = Field(alias="readRoles")
    write_roles: list[str] = Field(alias="writeRoles")
    encryption: EncryptionMode
    max_body_bytes: int = Field(gt=0, alias="maxBodyBytes")
    rate_limit: CollectionRateLimitConfig | None = Field(default=None, alias="rateLimit")
    """Enable rate limiting for push operations on this collection.

    Accepts ``true`` (use global defaults), ``false``/``null`` (disabled),
    or an object ``{"windowMs": …, "maxRequests": …}`` to override specific
    global values.  Requires a global ``rateLimit`` config to be set."""

    cache_duration_ms: int | None = Field(default=None, gt=0, alias="cacheDurationMs")
    """Custom ``Cache-Control: max-age`` duration (in milliseconds) for pull responses.

    When set, the server adds a ``Cache-Control`` header to GET pull responses
    so that downstream proxies or clients can cache the response.
    ``None`` (default) means no ``Cache-Control`` header is added."""

    object_schema: dict[str, Any] | None = Field(default=None, alias="objectSchema")
    """Optional JSON Schema that pushed data objects must conform to.

    When set, every push validates ``body.data`` against this schema before
    writing.  Invalid payloads are rejected with ``400``.
    Requires the ``jsonschema`` package (``pip install jsonschema``)."""

    allowed_mime_types: list[str] = Field(
        default_factory=lambda: ["application/json"],
        alias="allowedMimeTypes",
    )
    """MIME types this collection accepts on push.

    Defaults to ``["application/json"]`` (standard JSON sync protocol).
    Set to other types (e.g. ``["image/png", "image/jpeg"]`` or ``["image/*"]``)
    to create a binary collection that accepts raw file uploads.
    Supports wildcard patterns via ``fnmatch`` (e.g. ``image/*``).

    Binary collections (those without ``application/json``) use simple
    overwrite semantics — no conflict detection, no timestamps, no
    incremental sync."""

    pull_only: bool | None = Field(default=None, alias="pullOnly")
    push_only: bool | None = Field(default=None, alias="pushOnly")
    force_full_fetch: bool | None = Field(default=None, alias="forceFullFetch")
    client_encrypted: bool | None = Field(default=None, alias="clientEncrypted")
    bundle: str | None = Field(default=None, min_length=1)
    remote: RemoteConfig | None = Field(default=None)
    """When set, this collection is replicated from a remote primary starfish server.
    All replica behavior (write mode, sync triggers, interval, auth) is fully described here."""

    queue: QueueConfig | None = Field(default=None)
    """When set, the server publishes a change event to the configured queue
    after every successful push.

    Accepts ``true`` (use defaults — topic is the collection name),
    ``false``/``null`` (disabled), or an object ``{"topic": …, "includeParams": …}``
    to customise."""

    ttl_ms: int | None = Field(default=None, gt=0, alias="ttlMs")
    """Document time-to-live in milliseconds.

    When set, documents whose last-modified timestamp is older than ``ttl_ms``
    are treated as empty on pull — the server returns ``{"data": {}, "hash": …}``
    as if the document were never written."""

    field_permissions: dict[str, "FieldPermission"] | None = Field(default=None, alias="fieldPermissions")
    """Per-field read/write permissions.

    Keys are top-level field names in the document data.  Only fields listed
    here are access-controlled; unlisted fields inherit the collection's roles.

    Example::

        field_permissions={"secret": FieldPermission(write_roles=["admin"])}
    """

    @field_validator("rate_limit", mode="before")
    @classmethod
    def _coerce_rate_limit(cls, v: object) -> object:
        if v is True:
            return CollectionRateLimitConfig()
        if v is False:
            return None
        return v

    @field_validator("queue", mode="before")
    @classmethod
    def _coerce_queue(cls, v: object) -> object:
        if v is True:
            return QueueConfig()
        if v is False:
            return None
        return v


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    model_config = {"populate_by_name": True}

    window_ms: int = Field(gt=0, alias="windowMs")
    max_requests: int = Field(gt=0, alias="maxRequests")


class NamespaceConfig(BaseModel):
    """A named sub-router that groups collections under a URL prefix.

    Each key in ``SyncConfig.namespaces`` becomes a URL prefix so that
    collections are mounted at ``/{name}/pull/…`` and ``/{name}/push/…``.
    """

    model_config = {"populate_by_name": True}

    collections: list[CollectionConfig]


class SyncConfig(BaseModel):
    """Top-level sync configuration."""

    model_config = {"populate_by_name": True}

    version: Literal[1]
    collections: list[CollectionConfig]
    namespaces: dict[str, NamespaceConfig] | None = Field(default=None)
    """Named sub-routers for multi-tenant isolation.

    Keys must match ``[a-zA-Z0-9_-]+`` and must not be the reserved names
    ``pull``, ``push``, ``health``, or ``batch``.
    Each namespace must contain at least one collection.

    Example::

        namespaces={
            "acme": NamespaceConfig(collections=[settings_col]),
            "globex": NamespaceConfig(collections=[settings_col]),
        }
    """
    rate_limit: RateLimitConfig | None = Field(default=None, alias="rateLimit")
