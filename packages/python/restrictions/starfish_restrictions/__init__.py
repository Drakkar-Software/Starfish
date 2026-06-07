"""``starfish-restrictions`` — identity action restrictions extension.

A server-side extension that denies access for a list of identities, scoped to
the whole server, a namespace, a collection, or a single action (pull / push /
list). Identity lists are static sequences or callbacks, and may also be
declared statically in the serializable ``SyncConfig`` (``restrictions`` fields).

Plug it into the server through ``SyncRouterOptions.plugins`` via the
``authorize`` hook it contributes::

    from starfish_restrictions import create_restrictions_plugin

    create_sync_router(SyncRouterOptions(
        store=store, config=config, role_resolver=role_resolver,
        plugins=[default_server_plugin, create_restrictions_plugin(config=config)],
    ))
"""

from starfish_restrictions.restrictions_plugin import (
    ROOT,
    IdentitySource,
    RestrictionAction,
    RestrictionRule,
    RestrictionScope,
    create_restrictions_plugin,
    restrictions_from_config,
)

__all__ = [
    "ROOT",
    "IdentitySource",
    "RestrictionAction",
    "RestrictionRule",
    "RestrictionScope",
    "create_restrictions_plugin",
    "restrictions_from_config",
]
