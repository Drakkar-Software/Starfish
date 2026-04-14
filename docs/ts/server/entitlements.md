# Entitlements

Entitlements let you gate collection access behind named feature slugs — for example
`"premium-package-1"` or `"paid-cloud-sync"` — without changing `CollectionConfig`'s schema.
An admin writes a per-user entitlement document; the server translates slugs into roles at
request time; collections declare which roles they require.

> **Prerequisites:** [Group Access Control](group-access.md), [Collection Patterns](../client/19-collection-patterns.md)

---

## How it works

```
Admin pushes { features: ["premium-package-1"] }
         ↓
EntitlementRoleEnricher reads doc on each request
         ↓
Grants role "entitlement:premium-package-1" to that user
         ↓
Collection with readRoles: ["entitlement:premium-package-1"] → 200
Other users → 403
```

No new config fields. `readRoles`/`writeRoles` stay string arrays; entitlement roles are
just strings that follow the `"entitlement:{slug}"` convention.

---

## Server setup

### 1 — Define the collections

```ts
// TypeScript
const config: SyncConfig = {
  version: 1,
  collections: [
    // Entitlement document — admin writes, user reads their own
    {
      name: "entitlements",
      storagePath: "users/{identity}/entitlements",
      readRoles: ["self"],      // auto-granted when {identity} matches caller
      writeRoles: ["admin"],    // only admins can grant/revoke features
      encryption: "none",
      maxBodyBytes: 4096,
      allowedMimeTypes: ["application/json"],
    },

    // Gated collection — requires the premium-package-1 entitlement to read
    {
      name: "premium-content",
      storagePath: "premium/{contentId}",
      readRoles: ["entitlement:premium-package-1"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 131_072,
      allowedMimeTypes: ["application/json"],
    },
  ],
}
```

```python
# Python
config = SyncConfig(
    version=1,
    collections=[
        CollectionConfig(
            name="entitlements",
            storage_path="users/{identity}/entitlements",
            read_roles=["self"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=4096,
        ),
        CollectionConfig(
            name="premium-content",
            storage_path="premium/{contentId}",
            read_roles=["entitlement:premium-package-1"],
            write_roles=["admin"],
            encryption="none",
            max_body_bytes=131_072,
        ),
    ],
)
```

### 2 — Wire the enricher

```ts
// TypeScript
import {
  createEntitlementRoleEnricher,
  composeEnrichers,
} from "@drakkar.software/starfish-server"

const entitlementEnricher = createEntitlementRoleEnricher({ store })

const syncRouter = createSyncRouter({
  store,
  config,
  roleResolver,
  // composeEnrichers runs all enrichers in parallel and merges results
  roleEnricher: composeEnrichers(entitlementEnricher),
})
```

```python
# Python
from starfish_server import (
    create_entitlement_role_enricher,
    EntitlementRoleEnricherOptions,
    compose_enrichers,
)

entitlement_enricher = create_entitlement_role_enricher(
    EntitlementRoleEnricherOptions(store=store)
)

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    role_enricher=compose_enrichers(entitlement_enricher),
))
```

### Combining with a group enricher

```ts
roleEnricher: composeEnrichers(
  createGroupRoleEnricher({ store, membersPath: "groups/{groupId}/members", groupParam: "groupId" }),
  createEntitlementRoleEnricher({ store }),
)
```

```python
role_enricher = compose_enrichers(
    create_group_role_enricher(GroupRoleEnricherOptions(
        store=store, members_path="groups/{groupId}/members", group_param="groupId",
    )),
    create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store)),
)
```

---

## Entitlement document format

The document stored at `users/{userId}/entitlements`:

```json
{
  "features": ["premium-package-1", "paid-cloud-sync"]
}
```

The enricher reads `data.features` (configurable via `field` option), maps each string to
`"entitlement:{slug}"`, and adds those roles to the caller's effective role set for the
duration of the request.

---

## `createEntitlementRoleEnricher` options

| Option | Type | Default | Description |
|---|---|---|---|
| `store` | `ObjectStore` | — | Object store to read entitlement documents from |
| `path` | `string` | `"users/{identity}/entitlements"` | Storage path template; `{identity}` is replaced with `auth.identity` |
| `field` | `string` | `"features"` | Field inside `data` holding the slug array |
| `rolePrefix` | `string` | `"entitlement"` | Prefix for generated role strings |
| `cacheTtlMs` | `number` | `60000` | Cache TTL in ms per user; set to `0` to disable |

Python uses `snake_case`: `role_prefix`, `cache_ttl_ms`.

### Role prefix collision

If your application already uses `"entitlement:"` for another purpose, set a different prefix:

```ts
createEntitlementRoleEnricher({ store, rolePrefix: "feature" })
// Grants "feature:premium-package-1" instead
```

Then update `readRoles` to match: `readRoles: ["feature:premium-package-1"]`.

---

## Storing entitlements (admin operations)

Entitlement documents are regular Starfish JSON documents. Admins push to them using the
standard push API.

### TypeScript

```ts
// Grant entitlements
const existing = await adminClient.pull(`/pull/users/${userId}/entitlements`)
const current: string[] = (existing.data as any)?.features ?? []
await adminClient.push(
  `/push/users/${userId}/entitlements`,
  { features: [...new Set([...current, "premium-package-1"])] },
  existing.hash,  // hash-based conflict detection
)

// Revoke an entitlement
const fresh = await adminClient.pull(`/pull/users/${userId}/entitlements`)
const remaining = ((fresh.data as any)?.features ?? []).filter(
  (f: string) => f !== "premium-package-1",
)
await adminClient.push(
  `/push/users/${userId}/entitlements`,
  { features: remaining },
  fresh.hash,
)
```

### Python

```python
# Grant entitlements
existing = await admin_client.pull(f"/pull/users/{user_id}/entitlements")
current = (existing.data or {}).get("features", [])
updated = list(set(current + ["premium-package-1"]))
await admin_client.push(
    f"/push/users/{user_id}/entitlements",
    {"features": updated},
    existing.hash,  # hash-based conflict detection
)

# Revoke an entitlement
fresh = await admin_client.pull(f"/pull/users/{user_id}/entitlements")
remaining = [f for f in (fresh.data or {}).get("features", []) if f != "premium-package-1"]
await admin_client.push(
    f"/push/users/{user_id}/entitlements",
    {"features": remaining},
    fresh.hash,
)
```

**Conflict safety:** always read the current document and pass its `hash` as `baseHash` /
`base_hash` when pushing. If two admins update the same user simultaneously, the second push
gets a 409 conflict and must re-read before retrying.

**Cache timing:** after an admin updates the entitlement document, the enricher's in-memory
cache may serve stale data for up to `cacheTtlMs` (default 60 seconds). For immediate
propagation, set `cacheTtlMs: 0` and use an external cache layer, or accept the propagation
delay.

---

## Client-side: reading entitlements

The `pullEntitlements` helper fetches a user's feature slug list. Returns `[]` if the document
doesn't exist yet — no error handling needed.

### TypeScript

```ts
import { pullEntitlements } from "@drakkar.software/starfish-client"

const features = await pullEntitlements(client, userId)
// e.g. ["premium-package-1", "paid-cloud-sync"]

if (features.includes("paid-cloud-sync")) {
  // enable cloud sync UI
}
```

### Python

```python
from starfish_sdk import pull_entitlements

features = await pull_entitlements(client, user_id)
# e.g. ["premium-package-1", "paid-cloud-sync"]

if "paid-cloud-sync" in features:
    # enable cloud sync UI
    pass
```

### `pullEntitlements` options

| Option | TS type | Python type | Default | Description |
|---|---|---|---|---|
| `path` | `string` | `str` | `"/pull/users/{userId}/entitlements"` | Path template; `{userId}` / `{user_id}` is replaced with the user ID |
| `field` | `string` | `str` | `"features"` | Field name in the document `data` object |

---

## Allowing users to self-manage entitlements

By default only admins can write entitlement documents. To let users manage their own
entitlements (e.g. a free-tier toggle or in-app purchase webhook), add `"self"` to
`writeRoles`:

```ts
{
  name: "entitlements",
  storagePath: "users/{identity}/entitlements",
  readRoles: ["self"],
  writeRoles: ["admin", "self"],  // user can also write
  ...
}
```

In this case validate the feature list in your `roleResolver` or use `objectSchema` to
restrict which slugs a user may grant themselves.

---

## Read/write asymmetry

Collections can require different entitlements for read vs. write:

```ts
{
  name: "collaborative-doc",
  storagePath: "docs/{docId}",
  readRoles: ["entitlement:viewer-plan"],   // read: viewer or above
  writeRoles: ["entitlement:editor-plan"],  // write: editor only
  ...
}
```

---

## Related

- [Role Enrichers](../client/19-collection-patterns.md) — group-based access control
- [Collection Patterns](../client/19-collection-patterns.md) — general RBAC patterns
- [Audit Logging](audit.md) — log which identity accessed which collection and when
