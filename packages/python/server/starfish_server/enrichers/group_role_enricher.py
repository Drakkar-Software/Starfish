"""Group-based role enricher for Starfish."""


import json
import logging
import time
from dataclasses import dataclass
from typing import Literal

from starfish_server.storage.base import AbstractObjectStore
from starfish_server.router.route_builder import AuthResult, RoleEnricher


@dataclass(frozen=True)
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

    candidacy_path: str | None = None
    """Storage path template for individual candidacy documents.

    Must contain a placeholder matching :attr:`group_param` and ``{identity}``
    (substituted with the requesting user's identity at runtime).
    When ``None``, the candidacy feature is disabled globally.
    Setting this option is a global prerequisite; candidacy must also be enabled
    per-group via :attr:`candidacy_enabled_field` in each group's members document.
    Example: ``"groups/{groupId}/candidacies/{identity}"``
    """

    candidacy_role: str = "group-candidate"
    """Role string granted to users with a pending candidacy.
    Defaults to ``"group-candidate"``."""

    candidacy_status_field: str = "status"
    """Field name in the candidacy document data holding the application status.
    Expected values: ``"pending"``, ``"accepted"``, ``"denied"``.
    Defaults to ``"status"``."""

    candidacy_enabled_field: str = "candidacyEnabled"
    """Field name in the members document data enabling candidacy for a specific group.
    When absent or falsy, candidacy is disabled for that group regardless of the
    global setting.  Defaults to ``"candidacyEnabled"``."""

    candidacy_cache_ttl_ms: int | None = None
    """How long (ms) to cache candidacy document lookups.
    ``None`` defaults to :attr:`cache_ttl_ms`.  Set to 0 to disable."""


@dataclass
class _MembersCacheEntry:
    members: frozenset[str]
    candidacy_enabled: bool
    expires_at: float


_CandidacyStatus = Literal["pending", "accepted", "denied"]


@dataclass
class _CandidacyCacheEntry:
    status: _CandidacyStatus | None
    expires_at: float


def create_group_role_enricher(opts: GroupRoleEnricherOptions) -> RoleEnricher:
    """Return a :class:`RoleEnricher` that grants a role to group members.

    The members document must be a standard Starfish JSON document whose
    ``data`` field contains a string list under ``opts.members_field``
    (default ``"members"``):

    .. code-block:: json

        { "members": ["alice", "bob", "charlie"] }

    When ``opts.candidacy_path`` is set, users can apply to join a group by
    pushing a candidacy document with ``{ "status": "pending", "message": "..." }``.
    Pending applicants receive ``opts.candidacy_role`` (default ``"group-candidate"``)
    until an admin accepts or denies the application.  Candidacy must also be
    enabled per-group by setting ``candidacyEnabled: true`` in the members document.

    Usage::

        enricher = create_group_role_enricher(GroupRoleEnricherOptions(
            store=store,
            members_path="groups/{groupId}/members",
            group_param="groupId",
            candidacy_path="groups/{groupId}/candidacies/{identity}",
        ))

        router = create_sync_router(SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            role_enricher=enricher,
        ))
    """
    # Construction-time validation
    if opts.cache_ttl_ms < 0:
        raise ValueError("cache_ttl_ms must be >= 0")
    if opts.candidacy_cache_ttl_ms is not None and opts.candidacy_cache_ttl_ms < 0:
        raise ValueError("candidacy_cache_ttl_ms must be >= 0")
    if f"{{{opts.group_param}}}" not in opts.members_path:
        raise ValueError(
            f'members_path "{opts.members_path}" must contain the '
            f"{{{opts.group_param}}} placeholder"
        )
    if opts.candidacy_path is not None:
        if not opts.candidacy_path:
            raise ValueError("candidacy_path must not be empty")
        if "{identity}" not in opts.candidacy_path:
            raise ValueError(
                f'candidacy_path "{opts.candidacy_path}" must contain the {{identity}} placeholder'
            )
        if f"{{{opts.group_param}}}" not in opts.candidacy_path:
            raise ValueError(
                f'candidacy_path "{opts.candidacy_path}" must contain the '
                f"{{{opts.group_param}}} placeholder"
            )

    candidacy_cache_ttl_ms = (
        opts.candidacy_cache_ttl_ms
        if opts.candidacy_cache_ttl_ms is not None
        else opts.cache_ttl_ms
    )

    members_cache: dict[str, _MembersCacheEntry] = {}
    # candidacy_cache key: f"{group_id}\x00{identity}" — null byte separator avoids collisions
    # when group_id or identity values contain colons or other separator characters.
    candidacy_cache: dict[str, _CandidacyCacheEntry] = {}

    async def resolve_members_doc(group_id: str) -> tuple[frozenset[str], bool]:
        now = time.monotonic() * 1000

        if opts.cache_ttl_ms > 0:
            entry = members_cache.get(group_id)
            if entry is not None and entry.expires_at > now:
                return entry.members, entry.candidacy_enabled

        key = opts.members_path.replace(f"{{{opts.group_param}}}", group_id)
        raw = await opts.store.get_string(key)

        if raw is None:
            return frozenset(), False

        try:
            # StoredDocument format: { "v": 1, "data": { "members": [...] }, ... }
            doc = json.loads(raw)
            data: dict[str, object] = doc.get("data", {}) or {}
            member_list = data.get(opts.members_field)
            members = (
                frozenset(m for m in member_list if isinstance(m, str))
                if isinstance(member_list, list)
                else frozenset()
            )
            candidacy_enabled = bool(data.get(opts.candidacy_enabled_field))

            if opts.cache_ttl_ms > 0:
                members_cache[group_id] = _MembersCacheEntry(
                    members=members,
                    candidacy_enabled=candidacy_enabled,
                    expires_at=now + opts.cache_ttl_ms,
                )
            return members, candidacy_enabled
        except (json.JSONDecodeError, AttributeError) as exc:
            logging.getLogger(__name__).error(
                "group-enricher: corrupt membership document at %r: %s", key, exc
            )
            # Do not cache corrupt result — return empty without writing to cache
            return frozenset(), False

    async def resolve_candidacy_status(
        group_id: str,
        identity: str,
    ) -> str | None:
        # Null byte separator prevents cache key collisions when group_id/identity contain colons
        cache_key = f"{group_id}\x00{identity}"
        now = time.monotonic() * 1000

        if candidacy_cache_ttl_ms > 0:
            entry = candidacy_cache.get(cache_key)
            if entry is not None and entry.expires_at > now:
                return entry.status

        # Only substitute the group param and {identity} — never loop over all URL params,
        # as a URL param named "identity" would shadow the auth identity substitution.
        key = (
            opts.candidacy_path  # type: ignore[union-attr]  # guarded by caller
            .replace(f"{{{opts.group_param}}}", group_id)
            .replace("{identity}", identity)
        )

        raw = await opts.store.get_string(key)

        if raw is None:
            return None

        try:
            # StoredDocument format: { "v": 1, "data": { "status": "..." }, ... }
            doc = json.loads(raw)
            s = doc.get("data", {}).get(opts.candidacy_status_field)
            status: _CandidacyStatus | None = (
                s if s in ("pending", "accepted", "denied") else None
            )

            if candidacy_cache_ttl_ms > 0:
                candidacy_cache[cache_key] = _CandidacyCacheEntry(
                    status=status,
                    expires_at=now + candidacy_cache_ttl_ms,
                )
            return status
        except (json.JSONDecodeError, AttributeError) as exc:
            logging.getLogger(__name__).error(
                "group-enricher: corrupt candidacy document at %r: %s", key, exc
            )
            # Do not cache corrupt result — return None without writing to cache
            return None

    async def group_role_enricher(
        auth: AuthResult,
        params: dict[str, str],
    ) -> list[str]:
        group_id = params.get(opts.group_param)
        if not group_id:
            return []

        members, candidacy_enabled = await resolve_members_doc(group_id)

        if auth.identity in members:
            return [opts.role]

        if not opts.candidacy_path:
            return []
        if not candidacy_enabled:
            return []

        status = await resolve_candidacy_status(group_id, auth.identity)
        return [opts.candidacy_role] if status == "pending" else []

    return group_role_enricher
