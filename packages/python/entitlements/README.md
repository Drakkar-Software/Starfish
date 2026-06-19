> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-entitlements

Starfish entitlements extension for Python — gate collection access on a per-user feature-slug document.
The server-side `create_entitlement_role_enricher` reads a user's entitlement document and grants
`entitlement:<slug>` roles; the client-side `pull_entitlements` reads the same document for UI gating.

## Install

```sh
pip install starfish-sdk starfish-server starfish-entitlements
```

## Client usage

```python
from starfish_entitlements import pull_entitlements

features = await pull_entitlements(client, user_id)
# e.g. ["premium-package-1", "paid-cloud-sync"]

if "paid-cloud-sync" in features:
    ...  # unlock cloud sync UI
```

## Server usage

```python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_entitlements import create_entitlement_role_enricher, EntitlementRoleEnricherOptions

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    role_enricher=create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store)),
))
```

Compose it alongside your own enrichers with `compose_enrichers` from
`starfish_server`:

```python
from starfish_server import compose_enrichers
from starfish_entitlements import create_entitlement_role_enricher, EntitlementRoleEnricherOptions

async def team_enricher(auth, params):
    if await is_team_member(auth.identity, params.get("teamId")):
        return ["team-member"]
    return []

role_enricher = compose_enrichers(
    team_enricher,
    create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store)),
)
```

See `docs/ts/entitlements/` for the full guide (the Python API mirrors the TypeScript one).
