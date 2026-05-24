# Collection Namespaces

Namespaces let you group collections under a URL prefix: `/{namespace}/pull/...` and `/{namespace}/push/...`. Collections without a namespace continue to work at `/pull/...` and `/push/...`.

## When to use namespaces

- **Multi-tenant isolation** — different tenants share one server but have separate route prefixes
- **Logical grouping** — organise collections by domain (e.g. `/chat/pull/...`, `/crm/pull/...`)
- **Versioning** — version collections independently (`/v1/pull/...`, `/v2/pull/...`)

## Server configuration

Add a `namespaces` field alongside `collections` in `SyncConfig`:

```ts
import { createSyncRouter, type SyncConfig, type NamespaceConfig } from "@drakkar.software/starfish-server"

const config: SyncConfig = {
  version: 1,

  // Root-level collections — accessible at /pull/... and /push/...
  collections: [
    {
      name: "public-announcements",
      storagePath: "announcements/global",
      readRoles: ["public"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
  ],

  // Namespaced collections — accessible at /{namespace}/pull/... and /{namespace}/push/...
  namespaces: {
    tenantA: {
      collections: [
        {
          name: "settings",
          storagePath: "tenantA/users/{identity}/settings",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 65_536,
          allowedMimeTypes: ["application/json"],
        },
        {
          name: "notes",
          storagePath: "tenantA/users/{identity}/notes",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "delegated",
          maxBodyBytes: 131_072,
          allowedMimeTypes: ["application/json"],
        },
      ],
    },
    tenantB: {
      collections: [
        {
          name: "settings",    // Same name as tenantA — valid
          storagePath: "tenantB/users/{identity}/settings",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 65_536,
          allowedMimeTypes: ["application/json"],
        },
      ],
    },
  },
}

const syncRouter = createSyncRouter({ store, config, roleResolver })
app.route("/v1", syncRouter)
```

Routes produced by the config above:

```
GET  /v1/pull/announcements/global
POST /v1/push/announcements/global
GET  /v1/tenantA/pull/tenantA/users/:identity/settings
POST /v1/tenantA/push/tenantA/users/:identity/settings
GET  /v1/tenantA/pull/tenantA/users/:identity/notes
POST /v1/tenantA/push/tenantA/users/:identity/notes
GET  /v1/tenantB/pull/tenantB/users/:identity/settings
POST /v1/tenantB/push/tenantB/users/:identity/settings
```

## Client usage

The `StarfishClient` and `SyncManager` both use explicit paths. Include the namespace prefix in your paths:

```ts
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// Include the namespace in the path
const sync = new SyncManager({
  client,
  pullPath: `/tenantA/pull/tenantA/users/${creds.userId}/settings`,
  pushPath: `/tenantA/push/tenantA/users/${creds.userId}/settings`,
})

await sync.pull()
await sync.push({ theme: "dark" })
```

## Namespace-scoped batch pull

Each namespace has its own `/{namespace}/batch/pull` endpoint that only searches within that namespace. The root `/batch/pull` only searches root collections.

```ts
// Fetch multiple collections in the tenantA namespace
const res = await client.fetch(
  `https://api.example.com/v1/tenantA/batch/pull?collections=settings,notes`,
  { headers: await client.getAuthHeaders() }
)
```

## Storage isolation

Namespaces are **URL prefixes only**. Two collections with the same `storagePath` in different namespaces share the same underlying data. For true data isolation, use distinct storagePaths per namespace — prefix the path with the namespace name:

```ts
// ✅ Correct: distinct storagePaths give isolated data
namespaces: {
  tenantA: { collections: [{ storagePath: "tenantA/users/{identity}/data", ... }] },
  tenantB: { collections: [{ storagePath: "tenantB/users/{identity}/data", ... }] },
}

// ⚠️ Same storagePath in different namespaces means shared data
namespaces: {
  tenantA: { collections: [{ storagePath: "users/{identity}/data", ... }] },
  tenantB: { collections: [{ storagePath: "users/{identity}/data", ... }] },  // shares storage!
}
```

## Namespace name rules

- Must contain only letters, digits, hyphens (`-`), and underscores (`_`)
- Cannot be one of the reserved names: `pull`, `push`, `health`, `batch`

Valid examples: `tenantA`, `tenant-a`, `v1`, `crm_service`

## Bundles in namespaces

Bundled collections work the same way inside a namespace:

```ts
namespaces: {
  tenantA: {
    collections: [
      {
        name: "prefs",
        storagePath: "tenantA/users/{identity}/data",
        bundle: "userdata",
        encryption: "delegated",
        ...
      },
      {
        name: "profile",
        storagePath: "tenantA/users/{identity}/data",
        bundle: "userdata",
        encryption: "delegated",
        ...
      },
    ],
  },
}
// Bundle pull: GET /tenantA/pull/tenantA/users/:identity/data
// Returns: { collections: { prefs: {...}, profile: {...} }, timestamp: ... }
```
