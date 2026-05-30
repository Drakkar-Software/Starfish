"""Pydantic models for sync configuration."""


from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from starfish_server.constants import ENCRYPTION_NONE, ENCRYPTION_DELEGATED, APPEND_DEFAULT_FIELD

EncryptionMode = Literal["none", "delegated"]


class AppendOnlyConfig(BaseModel):
    """Append-only collection configuration.

    Tagged by ``type`` so new strategies can be added later; only
    ``"by_timestamp"`` is supported today (each element is stored as
    ``{ts, data}`` and pulls filter by ``ts`` via ``?checkpoint=``).

    When set on a :class:`CollectionConfig`, every push appends the incoming data
    object as the last element of a stored array, recorded as ``{ts, data}``.
    """

    model_config = {"populate_by_name": True}

    type: str
    """Discriminator.  Only ``"by_timestamp"`` is currently supported; an unknown
    value is rejected by :func:`validate_config` (mirrors the TS validator, which
    types this as the ``"by_timestamp"`` literal but defers the runtime check)."""

    field: str | None = Field(default=APPEND_DEFAULT_FIELD)
    """Array field name in the stored document.  Defaults to ``"items"``."""

    persist: bool | None = Field(default=True)
    """``True`` (default) — append item to stored array as ``{ts, data}``.
    ``False`` — compute hash and emit a write event without writing to storage
    (consumed by a plugin such as ``starfish-queuing``; replaces the old
    ``queueOnly`` behaviour)."""

    max_items: int | None = Field(default=None, alias="maxItems")
    """Opt-in cap: reject an append once the stored element count has reached this
    many, with ``409 {"error": "append_limit_exceeded", "limit": ...}``. ``None`` =
    unlimited. Bounds a single document; for higher volume, partition by a path
    parameter (e.g. ``storage_path="events/{date}"``). Requires ``persist`` (default)."""

    chunk_size: int | None = Field(default=None, alias="chunkSize")
    """Opt-in segmented storage: store the log as fixed-size sealed chunks of this
    many elements (plus a small head document) instead of one growing blob. Bounds
    append cost to O(chunk_size) (no O(n²) build) and lets ``?checkpoint=``/``?last=``
    pulls read only the chunks they need. ``None`` = single-document (legacy) layout.
    Recommended ~10000. Server-internal only — the wire format is unchanged. Requires
    ``persist`` (default)."""

    require_author_signature: bool = Field(default=True, alias="requireAuthorSignature")
    """Require a cryptographic author proof on every append (DEFAULT: ``True``).

    When enforced, an append MUST carry ``authorPubkey`` + ``authorSignature`` (an
    Ed25519 signature over the element ``data``, see
    ``starfish_protocol.sign_append_author``); the server verifies the signature
    and, when the auth layer identifies the caller (any cap-cert request), that
    ``authorPubkey`` equals the request presenter — so the stored author cannot be
    forged. The proof is stored on the element for readers to re-verify. Set
    ``False`` ONLY for an unauthenticated/public-write log where author identity is
    meaningless."""


RateLimitBucketMode = Literal["identity", "ip", "identity+ip"]


class RateLimitDimension(BaseModel):
    """One counted dimension of a two-independent rate-limit rule.

    ``window_ms`` / ``max_requests`` inherit from the rule, then the flat collection
    fields, then the global ``rateLimit`` config, when ``None``.
    """

    model_config = {"populate_by_name": True}

    window_ms: int | None = Field(default=None, gt=0, alias="windowMs")
    max_requests: int | None = Field(default=None, gt=0, alias="maxRequests")


class RateLimitRule(BaseModel):
    """A rate-limit rule for one collection action (push / pull / list).

    Two shapes (mutually exclusive):

    - **Single counter** — ``window_ms`` / ``max_requests`` with an optional ``bucket``.
    - **Two independent limits** — ``identity`` and/or ``ip`` sub-limits, each its own
      counter; the request is rejected if EITHER dimension is over budget. A rule using
      ``identity``/``ip`` must NOT also set ``bucket`` (rejected at config load).

    ``window_ms`` / ``max_requests`` inherit from the flat collection fields, then the
    global ``rateLimit`` config, when ``None``.
    """

    model_config = {"populate_by_name": True}

    window_ms: int | None = Field(default=None, gt=0, alias="windowMs")
    max_requests: int | None = Field(default=None, gt=0, alias="maxRequests")
    bucket: RateLimitBucketMode | None = None
    """How requests are grouped into a single counter. ``"identity"`` (default) keys by
    the authenticated caller, falling back to X-Forwarded-For / client IP / a shared
    "anonymous" bucket. ``"ip"`` keys strictly by IP, ignoring identity. ``"identity+ip"``
    keys by the (identity, ip) pair — one budget per distinct combination. The Python
    server can use the socket IP, so IP-based modes are reliable here (unlike the TS
    server, which has no portable socket IP)."""

    identity: RateLimitDimension | None = None
    """Two-independent form: per-identity dimension. Present ⇒ enforce a per-identity limit."""

    ip: RateLimitDimension | None = None
    """Two-independent form: per-ip dimension. Present ⇒ enforce a per-ip limit."""


class CollectionRateLimitConfig(BaseModel):
    """Per-collection rate limit config.

    Legacy flat fields (``window_ms`` / ``max_requests`` / ``bucket``) are treated
    as an implicit ``push`` rule (preserving the original push-only behavior) and as
    defaults for any explicit per-action rule that omits them. ``None`` fields fall
    back to the global ``rateLimit`` config. Passing an empty object (or
    ``"rateLimit": true`` in JSON) enables push rate limiting with the global defaults.
    """

    model_config = {"populate_by_name": True}

    window_ms: int | None = Field(default=None, gt=0, alias="windowMs")
    """Override the global window (in milliseconds) for this collection."""

    max_requests: int | None = Field(default=None, gt=0, alias="maxRequests")
    """Override the global max requests per window for this collection."""

    bucket: RateLimitBucketMode | None = None
    """Bucket mode for the legacy/implicit push rule. Default ``"identity"``."""

    push: RateLimitRule | None = None
    pull: RateLimitRule | None = None
    list: RateLimitRule | None = None


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
    bundle: str | None = Field(default=None, min_length=1)

    append_only: "AppendOnlyConfig | None" = Field(default=None, alias="appendOnly")
    """When set, every push appends the incoming data object as the last item of a stored array.

    Pass ``True`` as shorthand for ``AppendOnlyConfig()`` (all defaults).
    ``False``/``None`` disables append-only mode."""

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

    keyring_path: str | None = Field(default=None, alias="keyringPath")
    """Optional override for the keyring storage path.

    When omitted, defaults to ``<storage_path>/_keyring``.  Only relevant
    for collections using ``"delegated"`` encryption."""

    listable: bool | None = Field(default=None)
    """When ``True``, exposes a ``GET /list/...`` endpoint for this collection.

    The endpoint returns the existing document keys under the collection's
    prefix, allowing clients to discover which documents exist (e.g. which
    days have chat messages for a group).

    The last path parameter in ``storage_path`` is the value being
    enumerated.  Requires at least one path parameter; incompatible with
    ``appendOnly`` (persist=False) and ``bundle``."""

    root_only: bool | None = Field(default=None, alias="rootOnly")
    """When ``True``, only the **root device** (a self-signed device cap,
    ``iss == sub``) may access this collection; every paired/delegated device
    cap and member cap is rejected with ``403``, in addition to the normal
    read/write role checks.  Incompatible with public read/write roles
    (rejected at config load)."""

    @field_validator("rate_limit", mode="before")
    @classmethod
    def _coerce_rate_limit(cls, v: object) -> object:
        if v is True:
            return CollectionRateLimitConfig()
        if v is False:
            return None
        return v

    @field_validator("append_only", mode="before")
    @classmethod
    def _coerce_append_only(cls, v: object) -> object:
        # Boolean shorthand: ``True`` normalizes to ``{"type": "by_timestamp"}``.
        if v is True:
            return {"type": "by_timestamp"}
        if v is False:
            return None
        # Dict without ``type``: default the discriminator so a ``{field: "events"}``
        # shorthand still works. An explicit unknown ``type`` is preserved here and
        # rejected by ``validate_config``.
        if isinstance(v, dict) and "type" not in v:
            return {**v, "type": "by_timestamp"}
        return v


class ConfigEndpointOptions(BaseModel):
    """Controls authentication for the ``GET /config`` endpoint.

    Pass an instance to :attr:`SyncRouterOptions.config_endpoint` to enable the
    endpoint.  Omit (``None``) to disable it entirely (default).
    """

    model_config = {"populate_by_name": True}

    auth: Literal["public", "role-filtered"]
    """``"public"`` — no auth check, all collections returned.

    ``"role-filtered"`` — ``role_resolver`` runs; the caller sees only collections
    whose ``read_roles`` or ``write_roles`` intersect the caller's roles.
    On resolver error an empty collection list is returned (no 5xx surfaced)."""


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
