"""Group-based role enricher for Starfish."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.router.route_builder import AuthResult, RoleEnricher


@dataclass
class GroupRoleEnricherOptions:
    """Options for :func:`create_group_role_enricher`."""

    store: AbstractObjectStore
    """The ObjectStore to read membership documents from."""

    members_path: str
    """Storage path template for the members document.

    Must contain a placeholder matching :attr:`group_param`.
    Example: ``"groups/{groupId}/members"``
    """

    group_param: str
    """Name of the URL path parameter that identifies the group.

    Must appear in :attr:`members_path` and in the protected collection's
    ``storage_path``.  Example: ``"groupId"``
    """

    members_field: str = "members"
    """Top-level field in the members document data holding the list of
    member identity strings.  Defaults to ``"members"``."""

    role: str = "group-member"
    """Role string granted to members.  Defaults to ``"group-member"``."""

    cache_ttl_ms: int = 60_000
    """How long (in milliseconds) to cache membership lookups.
    Set to 0 to disable caching.  Defaults to 60 000 (1 minute)."""


@dataclass
class _CacheEntry:
    members: frozenset[str]
    expires_at: float


def create_group_role_enricher(opts: GroupRoleEnricherOptions) -> RoleEnricher:
    """Return a :class:`RoleEnricher` that grants a role to group members.

    The members document must be a standard Starfish JSON document whose
    ``data`` field contains a string list under ``opts.members_field``
    (default ``"members"``):

    .. code-block:: json

        { "members": ["alice", "bob", "charlie"] }

    Usage::

        enricher = create_group_role_enricher(GroupRoleEnricherOptions(
            store=store,
            members_path="groups/{groupId}/members",
            group_param="groupId",
        ))

        router = create_sync_router(SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            role_enricher=enricher,
        ))
    """
    cache: dict[str, _CacheEntry] = {}

    async def resolve_members(group_id: str) -> frozenset[str]:
        now = time.monotonic() * 1000

        if opts.cache_ttl_ms > 0:
            entry = cache.get(group_id)
            if entry is not None and entry.expires_at > now:
                return entry.members

        key = opts.members_path.replace(f"{{{opts.group_param}}}", group_id)
        raw = await opts.store.get_string(key)

        members: frozenset[str] = frozenset()
        if raw is not None:
            try:
                # StoredDocument format: { "v": 1, "data": { "members": [...] }, ... }
                doc = json.loads(raw)
                member_list = doc.get("data", {}).get(opts.members_field)
                if isinstance(member_list, list):
                    members = frozenset(m for m in member_list if isinstance(m, str))
            except (json.JSONDecodeError, AttributeError):
                # Corrupt document — treat as empty membership
                pass

        if opts.cache_ttl_ms > 0:
            cache[group_id] = _CacheEntry(
                members=members,
                expires_at=now + opts.cache_ttl_ms,
            )

        return members

    async def group_role_enricher(
        auth: AuthResult,
        params: dict[str, str],
    ) -> list[str]:
        group_id = params.get(opts.group_param)
        if not group_id:
            return []

        members = await resolve_members(group_id)
        return [opts.role] if auth.identity in members else []

    return group_role_enricher
