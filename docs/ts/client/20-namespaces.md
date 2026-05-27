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

### The `namespace` client option

Instead of hand-prefixing every path, pass `namespace` to `StarfishClient`. The client then
rewrites each request path to `/v1/{namespace}/…` for **both** the URL it hits and the canonical
path it signs — including the paths that namespace-unaware SDK helpers (keyring, blob uploads)
build internally, so you don't wrap or sub-class the client to reach a namespaced deployment.
With `namespace` set, `baseUrl` carries only the origin (and any reverse-proxy mount the proxy
strips), **not** the `/v1` segment.

```ts
const client = new StarfishClient({
  baseUrl: "https://api.example.com", // origin only — no /v1 here
  namespace: "tenantA",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// Pass plain action paths; the client inserts /v1/tenantA for you:
await client.pull(`/pull/tenantA/users/${creds.userId}/settings`)
// → GET https://api.example.com/v1/tenantA/pull/tenantA/users/:identity/settings
//   signed canonical: /v1/tenantA/pull/tenantA/users/:identity/settings
```

This mirrors the Python client's `namespace` parameter. Leave `namespace` unset (the default)
for a root-mounted server — paths pass through unchanged.

### Namespace with the React store bindings

The `useSyncInit` hook (zustand binding) builds its own `StarfishClient` from the config, so pass
`namespace` there too — keep `pullPath`/`pushPath` as bare action paths and the binding's client
prefixes them, exactly like a hand-built client:

```ts
const store = useSyncInit({
  serverUrl: "https://api.example.com", // origin only — no /v1 here
  namespace: "tenantA",
  pullPath: `/pull/users/${userId}/settings`, // bare; becomes /v1/tenantA/pull/...
  pushPath: `/push/users/${userId}/settings`,
})
```

Without this the store's pulls/pushes hit the un-namespaced path even when your standalone
`client.pull/push` calls are namespaced. The `legend`/`suspense` bindings act on an
already-built store and need no namespace of their own.

## Namespace-scoped batch pull

Each namespace has its own `/{namespace}/batch/pull` endpoint that only searches within that namespace. The root `/batch/pull` only searches root collections.

```ts
// Fetch multiple collections in the tenantA namespace
const res = await client.fetch(
  `https://api.example.com/v1/tenantA/batch/pull?collections=settings,notes`,
  { headers: await client.getAuthHeaders() }
)
```

### Resolving path parameters

Batch pull resolves `{param}` collections too. The `{identity}` param is **auto-filled from the
authenticated caller**, so a per-user collection like `users/{identity}/settings` works with no
extra arguments. Other params are supplied via an optional `params` query parameter — URL-encoded
JSON mapping each collection name to an **array of param-sets**, one per document to read. The
result for each name is an **array of entries** in the same order, so the SAME collection can fan
in many documents (e.g. many users' `profile`) in one round-trip:

```ts
const params = encodeURIComponent(JSON.stringify({
  notes: [{ teamId: "42" }],
  profile: [{ identity: "alice" }, { identity: "bob" }],
}))
const res = await client.fetch(
  `https://api.example.com/v1/tenantA/batch/pull?collections=settings,notes,profile&params=${params}`,
  { headers: await client.getAuthHeaders() }
)
// → { collections: {
//      settings: [{...own doc...}],            // no params → one auto-filled doc
//      notes:    [{...team 42...}],
//      profile:  [{...alice...}, {...bob...}],  // fanned in, in request order
//    } }
```

The typed SDK exposes this via `client.batchPull(names, { params })` and, for the common
"many docs of one collection" case, `client.batchPullMany("profile", [{ identity: "alice" }, …])`
which returns the entry array aligned to the param-sets by index.

Each entry is still authorized independently: a cap reads only the keys its `scope.paths`
covers, and a supplied identity that isn't the caller's is `Forbidden` (no `self` role). A required
param that is neither supplied nor auto-fillable returns `{ error: "Missing required path
parameter" }` for that document. The total number of reads across all collections is bounded by
`maxCollectionsPerBatch`.

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
