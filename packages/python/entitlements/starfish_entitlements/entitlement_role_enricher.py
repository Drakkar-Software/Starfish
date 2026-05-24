"""Entitlement-based role enricher for Starfish."""


import json
import logging
import time
from dataclasses import dataclass, field

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.router.route_builder import AuthResult, RoleEnricher


@dataclass
class EntitlementRoleEnricherOptions:
    """Options for :func:`create_entitlement_role_enricher`."""

    store: AbstractObjectStore
    """The ObjectStore to read entitlement documents from."""

    path: str = "users/{identity}/entitlements"
    """Storage path template for the per-user entitlement document.

    ``{identity}`` is replaced with the authenticated user's identity at runtime.
    Defaults to ``"users/{identity}/entitlements"``.
    """

    field: str = "features"
    """Top-level field in the entitlement document data holding the list of
    feature slugs.  Defaults to ``"features"``."""

    role_prefix: str = "entitlement"
    """Prefix applied to each feature slug when constructing the role string.

    A slug ``"premium-package-1"`` with prefix ``"entitlement"`` yields role
    ``"entitlement:premium-package-1"``.  Defaults to ``"entitlement"``.

    Change this if your role namespace already uses ``"entitlement:"`` for
    something else.
    """

    cache_ttl_ms: int = 60_000
    """How long (in milliseconds) to cache entitlement lookups per user.
    Set to 0 to disable caching.  Defaults to 60 000 (1 minute)."""


@dataclass
class _CacheEntry:
    features: frozenset[str]
    expires_at: float


def create_entitlement_role_enricher(opts: EntitlementRoleEnricherOptions) -> RoleEnricher:
    """Return a :class:`RoleEnricher` that grants roles from a per-user entitlement document.

    The entitlement document must be a standard Starfish JSON document whose
    ``data`` field contains a string list under ``opts.field`` (default ``"features"``):

    .. code-block:: json

        { "features": ["premium-package-1", "paid-cloud-sync"] }

    Each slug is translated to a role: ``f"{opts.role_prefix}:{slug}"``.  Collections
    gate access via ``read_roles`` / ``write_roles``:

    .. code-block:: python

        CollectionConfig(
            name="premium-data",
            read_roles=["entitlement:premium-package-1"],
            ...
        )

    Recommended entitlement collection config::

        CollectionConfig(
            name="entitlements",
            storage_path="users/{identity}/entitlements",
            read_roles=["self"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=4096,
        )

    Usage::

        enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))

        router = create_sync_router(SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            role_enricher=enricher,
        ))

    When combined with another enricher, use :func:`compose_enrichers`::

        from starfish_server import compose_enrichers
        role_enricher=compose_enrichers(group_enricher, entitlement_enricher)
    """
    cache: dict[str, _CacheEntry] = {}

    async def resolve_features(identity: str) -> frozenset[str]:
        now = time.monotonic() * 1000

        if opts.cache_ttl_ms > 0:
            entry = cache.get(identity)
            if entry is not None and entry.expires_at > now:
                return entry.features

        key = opts.path.replace("{identity}", identity)
        raw = await opts.store.get_string(key)

        features: frozenset[str] = frozenset()
        if raw is not None:
            try:
                # StoredDocument format: { "v": 1, "data": { "features": [...] }, ... }
                doc = json.loads(raw)
                feature_list = doc.get("data", {}).get(opts.field)
                if isinstance(feature_list, list):
                    features = frozenset(s for s in feature_list if isinstance(s, str))
            except (json.JSONDecodeError, AttributeError) as exc:
                logging.getLogger(__name__).error(
                    "entitlement-enricher: corrupt entitlement document at %r: %s", key, exc
                )
                # Corrupt document — treat as no entitlements, but do NOT cache
                # the empty result (matching the TS enricher): a transient
                # corruption must not deny entitlement roles for the whole TTL
                # after the document is repaired.
                return features

        if opts.cache_ttl_ms > 0:
            cache[identity] = _CacheEntry(
                features=features,
                expires_at=now + opts.cache_ttl_ms,
            )

        return features

    async def entitlement_role_enricher(
        auth: AuthResult,
        params: dict[str, str],
    ) -> list[str]:
        features = await resolve_features(auth.identity)
        return [f"{opts.role_prefix}:{slug}" for slug in features]

    return entitlement_role_enricher
