"""``starfish-entitlements`` — feature-slug entitlements extension.

Public surface: the client-side ``pull_entitlements`` reader for a user's
feature-slug document, and the server-side ``create_entitlement_role_enricher``
factory that turns those slugs into ``entitlement:<slug>`` roles.

The enricher plugs into the server through ``SyncRouterOptions.role_enricher``
(compose it with other enrichers via ``compose_enrichers`` from
``starfish_server``).
"""

from starfish_entitlements.entitlements import pull_entitlements


def __getattr__(name: str):
    """Lazy import of the server-side enricher so apps that only use the
    client-side ``pull_entitlements`` helper don't pay the ``starfish_server``
    import cost.
    """
    if name in ("EntitlementRoleEnricherOptions", "create_entitlement_role_enricher"):
        from starfish_entitlements import entitlement_role_enricher as _mod
        return getattr(_mod, name)
    raise AttributeError(f"module 'starfish_entitlements' has no attribute {name!r}")


__all__ = [
    "pull_entitlements",
    "EntitlementRoleEnricherOptions",
    "create_entitlement_role_enricher",
]
