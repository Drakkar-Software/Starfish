# @drakkar.software/starfish-entitlements

Starfish entitlements extension — gate collection access on a per-user feature-slug document. The
server-side `createEntitlementRoleEnricher` reads a user's entitlement document and grants
`entitlement:<slug>` roles; the client-side `pullEntitlements` reads the same document for UI gating.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-server @drakkar.software/starfish-entitlements
```

## Client usage

```ts
import { pullEntitlements } from "@drakkar.software/starfish-entitlements"

const features = await pullEntitlements(client, userId)
// e.g. ["premium-package-1", "paid-cloud-sync"]

if (features.includes("paid-cloud-sync")) {
  // unlock cloud sync UI
}
```

## Server usage

```ts
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"

const router = createSyncRouter({
  store,
  config,
  roleResolver,
  roleEnricher: createEntitlementRoleEnricher({ store }),
})
```

Compose it alongside your own enrichers with `composeEnrichers` from
`@drakkar.software/starfish-server`:

```ts
import { composeEnrichers, type RoleEnricher } from "@drakkar.software/starfish-server"
import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"

const teamEnricher: RoleEnricher = async (auth, params) =>
  (await isTeamMember(auth.identity, params.teamId)) ? ["team-member"] : []

const roleEnricher = composeEnrichers(
  teamEnricher,
  createEntitlementRoleEnricher({ store }),
)
```

See `docs/ts/entitlements/` for the full guide.
