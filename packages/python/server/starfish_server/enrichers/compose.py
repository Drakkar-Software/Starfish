"""Utility for composing multiple RoleEnrichers into one."""


import asyncio

from starfish_server.router.route_builder import AuthResult, RoleEnricher


def compose_enrichers(*enrichers: RoleEnricher) -> RoleEnricher:
    """Compose multiple :class:`RoleEnricher` functions into one.

    All enrichers run concurrently via :func:`asyncio.gather` and their results
    are merged into a single flat list.  Use this when
    :class:`~starfish_server.router.route_builder.SyncRouterOptions` needs to
    combine several application-level enrichers — for example a custom
    team-membership enricher together with an entitlement enricher.

    ::

        from starfish_server import compose_enrichers
        from starfish_entitlements import create_entitlement_role_enricher

        async def team_enricher(auth, params):
            if await is_team_member(auth.identity, params.get("teamId")):
                return ["team-member"]
            return []

        role_enricher = compose_enrichers(
            team_enricher,
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
