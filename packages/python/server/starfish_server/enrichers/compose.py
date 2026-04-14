"""Utility for composing multiple RoleEnrichers into one."""

from __future__ import annotations

import asyncio

from starfish_server.router.route_builder import AuthResult, RoleEnricher


def compose_enrichers(*enrichers: RoleEnricher) -> RoleEnricher:
    """Compose multiple :class:`RoleEnricher` functions into one.

    All enrichers run concurrently via :func:`asyncio.gather` and their results
    are merged into a single flat list.  Use this when
    :class:`~starfish_server.router.route_builder.SyncRouterOptions` needs to
    combine several enrichers — for example a group membership enricher together
    with an entitlement enricher.

    ::

        from starfish_server import (
            compose_enrichers,
            create_group_role_enricher,
            create_entitlement_role_enricher,
        )

        role_enricher = compose_enrichers(
            create_group_role_enricher(GroupRoleEnricherOptions(
                store=store,
                members_path="groups/{groupId}/members",
                group_param="groupId",
            )),
            create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store)),
        )

        router = create_sync_router(SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver,
            role_enricher=role_enricher,
        ))
    """

    async def _composed(auth: AuthResult, params: dict[str, str]) -> list[str]:
        results = await asyncio.gather(*(e(auth, params) for e in enrichers))
        return [role for sub in results for role in sub]

    return _composed
