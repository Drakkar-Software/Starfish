<p align="center">
  <img src="logo.png" alt="Starfish" width="400" />
</p>

# Starfish

A generic document sync library. Pull/push documents with hash-based conflict detection, incremental sync via timestamps, and role-based access control.

Works with any storage backend (S3, MongoDB, in-memory) and any auth model. The server determines roles; the library enforces permissions.

## Packages

### Server

| Package | Language | Description |
|---|---|---|
| `starfish-server` | Python | Protocol, encryption, config, FastAPI router, S3 storage |
| `@drakkar.software/starfish-server` | TypeScript | Protocol, encryption, config, Hono router, CF Workers compatible |

### Client SDKs

| Package | Language | Description |
|---|---|---|
| `@drakkar.software/starfish-client` | TypeScript | Browser, Node.js & React Native client with sync manager |
| `starfish-sdk` | Python | Async client (httpx) with sync manager |

## Quick Start

### Python Server

```python
from fastapi import FastAPI
from starfish_server import MemoryObjectStore, load_config, save_config
from starfish_server.router import create_sync_router, SyncRouterOptions, AuthResult

# In-memory store — no setup needed, data lost on restart
store = MemoryObjectStore()

# For production, use S3-compatible storage instead:
# from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions
# store = S3ObjectStore(S3StorageOptions(
#     access_key_id="...", secret_access_key="...",
#     endpoint="https://s3.amazonaws.com", bucket="my-bucket",
# ))

config = await load_config(store)

# Or load config from a JSON file instead of storage:
# from starfish_server import load_config_file
# config = load_config_file("config.json")

# Or parse a JSON string directly:
# from starfish_server import parse_config_json
# config = parse_config_json('{"version": 1, "collections": [...]}')

async def role_resolver(request):
    user = await verify_token(request.headers.get("authorization"))
    return AuthResult(identity=user.id, roles=user.roles)

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
))

app = FastAPI()
app.include_router(router, prefix="/v1")
```

### TypeScript Server (Hono / Cloudflare Workers)

```ts
import { Hono } from "hono"
import { createSyncRouter, MemoryObjectStore, parseConfigJson } from "@drakkar.software/starfish-server"
import type { AuthResult } from "@drakkar.software/starfish-server"

const store = new MemoryObjectStore(new Map())

// For Node.js filesystem storage:
// import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"
// const store = new FilesystemObjectStore({ baseDir: "./data" })

// For S3-compatible storage (requires: npm install @aws-sdk/client-s3):
// import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"
// const store = new S3ObjectStore({ accessKeyId: "...", secretAccessKey: "...", endpoint: "...", bucket: "..." })

const config = parseConfigJson(JSON.stringify({
  version: 1,
  collections: [{
    name: "settings",
    storagePath: "users/{identity}/settings",
    readRoles: ["self"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 65536,
  }],
}))

const sync = createSyncRouter({
  store,
  config,
  roleResolver: async (c) => {
    const user = await verifyToken(c.req.header("authorization"))
    return { identity: user.id, roles: user.roles } as AuthResult
  },
})

// Mount on a Hono app
const app = new Hono()
app.route("/v1", sync)
export default app // Works as a Cloudflare Worker
```

### Server Middleware

Both servers support optional middleware for production hardening. TypeScript uses `SyncRouterOptions`; Python uses `configure_middleware()`.

```ts
// TypeScript — pass options to createSyncRouter
const sync = createSyncRouter({
  store, config, roleResolver,
  cors: { origin: "https://app.example.com", credentials: true },
  securityHeaders: true,
  requestTimeoutMs: 30_000,
})
```

```python
# Python — configure middleware on the FastAPI app
from starfish_server.router.middleware import configure_middleware

app = FastAPI()
app.include_router(router, prefix="/v1")
configure_middleware(
    app,
    cors=True,
    security_headers=True,
    compression=True,
    request_timeout_ms=30_000,
)
```

Available middleware:

| Middleware | Description |
|-----------|-------------|
| CORS | Configurable origins, methods, headers, credentials |
| Security headers | X-Content-Type-Options, X-Frame-Options, HSTS, Referrer-Policy |
| Compression | GZip response compression (Python) |
| Request timeout | Returns 408 after configured timeout |
| ETag / 304 | Conditional requests via `If-None-Match` (automatic) |

### Graceful Shutdown

```ts
import { createGracefulShutdown } from "@drakkar.software/starfish-server"

const handle = createGracefulShutdown({
  replicaManager,
  queue,
  onShutdown: async () => { /* close DB connections */ },
})
// Registers SIGTERM/SIGINT handlers automatically
```

### Structured Logging & Audit

```ts
import { createJsonLogger, createCallbackAuditLogger } from "@drakkar.software/starfish-server"

const sync = createSyncRouter({
  store, config, roleResolver,
  logger: createJsonLogger(),
  auditLogger: createCallbackAuditLogger((entry) => {
    // { action: "push", collection: "settings", identity: "user-1", ... }
    writeToAuditDB(entry)
  }),
})
```

### OpenAPI Spec

```ts
import { generateOpenApiSpec } from "@drakkar.software/starfish-server"

const spec = generateOpenApiSpec(config, {
  title: "My Sync API",
  serverUrl: "https://api.example.com/v1",
})
// Serve at GET /openapi.json
```

## Protocol

Documents are synced using a pull/push model with hash-based optimistic concurrency.

**Pull** — `GET /pull/{storagePath}?checkpoint={ts}`
- Returns the full document data (or only changes since checkpoint)
- Always returns the hash of the full document

**Push** — `POST /push/{storagePath}`
```json
{ "data": { ... }, "baseHash": "abc123" }
```
- `baseHash` must match the current document hash (optimistic lock)
- `baseHash: null` for first push (document must not exist)
- Returns `409` on hash mismatch (conflict)
- Per-key timestamps track which fields changed when

## Config

Configuration can be loaded from multiple sources:

```python
# 1. From object storage (async — stored at __sync__/config.json)
config = await load_config(store)

# 2. From a JSON file on disk
from starfish_server import load_config_file
config = load_config_file("config.json")

# 3. From a JSON string
from starfish_server import parse_config_json
config = parse_config_json('{"version": 1, "collections": [...]}')

# 4. From Python objects directly
from starfish_server import SyncConfig, CollectionConfig
config = SyncConfig(version=1, collections=[
    CollectionConfig(name="notes", storagePath="users/{identity}/notes", ...),
])
```

TypeScript server:

```ts
import { parseConfigJson, loadConfig, saveConfig } from "@drakkar.software/starfish-server"

// 1. From a JSON string
const config = parseConfigJson('{"version": 1, "collections": [...]}')

// 2. From object storage (async — stored at __sync__/config.json)
const config = await loadConfig(store)

// 3. Save back to storage
await saveConfig(store, config)
```

Collection configuration is stored **inside the storage** at `__sync__/config.json`. Each collection defines:

```ts
{
  name: "invoices",                        // unique identifier
  storagePath: "users/{identity}/invoices", // document key template
  readRoles: ["self", "admin"],            // who can pull
  writeRoles: ["self"],                    // who can push
  encryption: "identity",                  // "none" | "identity" | "server"
  maxBodyBytes: 65536,                     // body size limit
}
```

### Namespaces

Group collections under a URL prefix for multi-tenant isolation or logical organisation. Collections without a namespace remain at `/pull/...` and `/push/...`.

```ts
const config: SyncConfig = {
  version: 1,
  collections: [
    // Root-level: /pull/announcements/global
    { name: "announcements", storagePath: "announcements/global", readRoles: ["public"], ... },
  ],
  namespaces: {
    tenantA: {
      collections: [
        // /tenantA/pull/tenantA/users/{identity}/settings
        { name: "settings", storagePath: "tenantA/users/{identity}/settings", readRoles: ["self"], ... },
      ],
    },
    tenantB: {
      collections: [
        // /tenantB/pull/tenantB/users/{identity}/settings
        { name: "settings", storagePath: "tenantB/users/{identity}/settings", readRoles: ["self"], ... },
      ],
    },
  },
}
```

> **Storage isolation**: The namespace is a URL prefix only. Use distinct `storagePath` values per namespace (e.g. prefix with the tenant name) to ensure data is stored separately.

See the [namespaces guide](docs/ts/client/20-namespaces.md) for full details.

### Conflict handling

A push returns `409` when the `baseHash` doesn't match the server's current hash — someone else wrote in between. The `SyncManager` handles this automatically:

1. Pull the latest remote state
2. Call your `onConflict` resolver with `(local, remote)` — default is a remote-wins deep merge
3. Push the merged result using the new hash
4. Repeat up to `maxRetries` times (default: 3), then raise `ConflictError`

Supply a custom resolver to implement your own merge strategy:

```python
# Python — field-level last-write-wins using per-key timestamps
def on_conflict(local, remote):
    return {**local, **remote}  # remote wins for every key

sync = SyncManager(client, pull_path, push_path, on_conflict=on_conflict)
```

```ts
// TypeScript
const sync = new SyncManager({
  client, pullPath, pushPath,
  onConflict: (local, remote) => ({ ...local, ...remote }), // local wins
})
```

### Roles

Roles are opaque strings resolved by your `roleResolver` callback. Two special roles:

- **`"public"`** — no authentication required
- **`"self"`** — auto-granted when `{identity}` in the URL matches the authenticated user's identity

Use `roleEnricher` for context-dependent roles (e.g. resource ownership):

```python
# Python
async def role_enricher(auth, params):
    if params.get("postId") and await is_owner(auth.identity, params["postId"]):
        return ["owner"]
    return []

router = create_sync_router(SyncRouterOptions(
    store=store, config=config,
    role_resolver=role_resolver, role_enricher=role_enricher,
))
```

```ts
// TypeScript
const router = createSyncRouter({
  store, config,
  roleResolver: async (c) => ({ identity: userId, roles: ["user"] }),
  roleEnricher: async (auth, params) => {
    if (params.postId && await isOwner(auth.identity, params.postId)) return ["owner"]
    return []
  },
})
```

### Encryption

- **`"none"`** — stored in plaintext
- **`"identity"`** — encrypted per-user with HKDF(secret, identity). Only the user can read their data.
- **`"server"`** — encrypted with a server-wide key. All server code can read; clients cannot read raw storage.
- **`"delegated"`** — client-side encryption. The server stores opaque encrypted data without decrypting it. See [Delegated encryption](#delegated-encryption).
- **`"group"`** — client-side encryption for multi-user collections. Each member holds their own X25519 key pair (derived deterministically from their passphrase); a shared Group Encryption Key is distributed per-member using ECDH key wrapping. Behaves identically to `"delegated"` on the server. See [Group Encryption](docs/ts/client/21-group-encryption.md).

## Client SDKs

All clients implement the same protocol: pull/push with hash-based conflict detection, incremental sync via checkpoints, optional E2E encryption, and automatic conflict resolution.

### TypeScript

Works in Browser, Node.js, and React Native (see [Platform Support](#platform-support)).

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async ({ method, path, body }) => ({
    Authorization: `Bearer ${await getToken()}`,
  }),
})

// Low-level: pull/push directly
const pulled = await client.pull("/pull/users/abc/settings")
await client.push("/push/users/abc/settings", { theme: "dark" }, pulled.hash)

// High-level: SyncManager handles conflicts automatically
const sync = new SyncManager({
  client,
  pullPath: "/pull/users/abc/settings",
  pushPath: "/push/users/abc/settings",
})

await sync.pull()
await sync.push({ theme: "dark", lang: "en" })
// Or: pull-modify-push in one call
await sync.update((data) => ({ ...data, theme: "light" }))
```

#### Full example: Auth + E2E Encryption + Author Signing

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"

// 1. Create client with auth
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async ({ method, path, body }) => ({
    "X-Pubkey": myPubkey,
    "X-Signature": await sign(method + path + (body ?? "")),
  }),
  // Optional: custom fetch for environments that need it
  // fetch: customFetch,
})

// 2. Create sync manager with encryption and signing
const sync = new SyncManager({
  client,
  pullPath: "/pull/users/abc/notes",
  pushPath: "/push/users/abc/notes",
  // E2E encryption: data is encrypted client-side before push,
  // decrypted after pull. The server never sees plaintext.
  encryptionSecret: "user-secret-key",
  encryptionSalt: "user-abc",
  encryptionInfo: "starfish-e2e", // optional, default: "starfish-e2e"
  // Author signing: sign data for provenance verification
  signData: async (data) => await sign(data),
  // Custom conflict resolver (default: remote-wins deep merge)
  onConflict: (local, remote) => ({ ...remote, ...local }),
  maxRetries: 3,
})

// 3. Sync
await sync.pull()
console.log(sync.getData()) // decrypted data

await sync.push({ notes: ["hello world"] }) // encrypted + signed automatically

// Or pull-modify-push in one call
await sync.update((current) => ({
  ...current,
  notes: [...(current.notes as string[]), "new note"],
}))
```

### Python

```python
from starfish_sdk import StarfishClient, SyncManager

async with StarfishClient(
    "https://api.example.com",
    auth=my_auth_provider,
    # namespace="my-ns"  # set when the server is behind a namespace-rewriting proxy
) as client:
    # Low-level
    pulled = await client.pull("/pull/users/abc/settings")
    await client.push("/push/users/abc/settings", {"theme": "dark"}, pulled.hash)

    # High-level
    sync = SyncManager(
        client,
        "/pull/users/abc/settings",
        "/push/users/abc/settings",
        encryption_secret="my-secret",
        encryption_salt="user-abc",
        # Optional: sign pushed data for author verification.
        # The callback receives stable_stringify(payload) — i.e. the
        # encrypted payload when encryption is active, or the raw data
        # when it is not — and must return a signature string.
        sign_data=my_signer,
    )
    await sync.pull()
    await sync.push({"theme": "dark", "lang": "en"})

    # Binary (blob) documents
    blob_result = await client.pull_blob("/pull/files/abc/photo.jpg")
    await client.push_blob("/push/files/abc/photo.jpg", b"...", blob_result.hash, "image/jpeg")

    # Entitlement discovery
    from starfish_sdk import pull_entitlements
    features = await pull_entitlements(client, "alice")
    # e.g. ["premium-package-1", "paid-cloud-sync"]
```

### Auth Provider

All clients use a generic auth provider that returns headers. This decouples the SDK from any specific auth scheme:

```ts
// Bearer token
auth: async () => ({ Authorization: `Bearer ${token}` })

// API key
auth: async () => ({ "X-API-Key": apiKey })

// Custom signing (e.g. blockchain, HMAC)
auth: async ({ method, path, body }) => ({
  "X-Pubkey": pubkey,
  "X-Signature": await sign(method + path + body),
})
```

### Client-Side Encryption

All clients support optional AES-256-GCM encryption with HKDF-derived keys. When enabled, data is encrypted before push and decrypted after pull — the server never sees plaintext.

> **Important:** The `encryptionSalt` (or `encryption_salt`) must be **deterministic** — all devices sharing the same secret must derive the same salt value. If each device generates its own salt (e.g., a random local ID), they will derive different encryption keys and will not be able to decrypt each other's data. A safe pattern is to derive the salt from the secret itself (e.g., `hash(secret).slice(0, 16)`).

You can also use the encryptor standalone:

```ts
import { createEncryptor } from "@drakkar.software/starfish-client"

const encryptor = createEncryptor("my-secret", "user-abc")
const encrypted = await encryptor.encrypt({ hello: "world" })
// => { _encrypted: "base64..." }
const decrypted = await encryptor.decrypt(encrypted)
// => { hello: "world" }
```

### Group Encryption

For multi-user encrypted collections (group chat, collaborative documents), use `encryption: "group"` on the server and `createGroupEncryptor` on the client. Each member derives their own X25519 key pair from their passphrase — no shared secret is required.

```ts
import { deriveGroupKeyPair, createGroupKeyring, createGroupEncryptor } from "@drakkar.software/starfish-client/group"
import { SyncManager } from "@drakkar.software/starfish-client"

// Admin creates a keyring for alice and bob
const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)
const { keyring, gek } = await createGroupKeyring(adminKp, {
  alice: alicePubKey,
  bob:   bobPubKey,
})
// Push keyring to Starfish, keep gek to add future members

// Member uses the keyring to create an encryptor
const myKp = await deriveGroupKeyPair(myPassphrase, myUserId)
const encryptor = await createGroupEncryptor(keyringData, myUserId, myKp.privateKey)

const sync = new SyncManager({
  client,
  pullPath: "/pull/groups/g1/notes",
  pushPath: "/push/groups/g1/notes",
  encryptor,   // replaces encryptionSecret/encryptionSalt
})
```

See [Group Encryption](docs/ts/client/21-group-encryption.md) for the full API including member addition and epoch rotation.

### Platform Support

The TypeScript client uses the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) and has zero production dependencies.

| Platform | Status | Notes |
|---|---|---|
| Browser | Works out of the box | Web Crypto API is native |
| Node.js >= 15 | Works out of the box | `crypto.subtle` available globally |
| React Native | Requires setup | See below |

#### React Native Setup

React Native's JS engines (Hermes, JSC) don't provide the Web Crypto API. Call `configurePlatform()` once at app startup before using the SDK:

```ts
import { configurePlatform } from "@drakkar.software/starfish-client"
import QuickCrypto from "react-native-quick-crypto"

configurePlatform({
  crypto: QuickCrypto,
  base64: {
    encode: (data) => Buffer.from(data).toString("base64"),
    decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

// Now use the SDK normally
import { SyncManager } from "@drakkar.software/starfish-client"
```

Alternatively, if your polyfill patches `globalThis.crypto` (e.g., `react-native-quick-crypto/polyfill`), no explicit configuration is needed.

### State Management with Zustand

The client ships with a built-in [Zustand](https://github.com/pmndrs/zustand) binding that wires sync, persistence, and offline-first writes together. Install Zustand as a peer dependency:

```bash
npm install zustand
# Optional: for draft-based mutations
npm install immer
```

#### Creating stores per collection

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"
import AsyncStorage from "@react-native-async-storage/async-storage"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
})

// One store per collection — each syncs independently
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
  }),
  // Browser: omit for localStorage (default)
  // React Native: pass AsyncStorage
  // No persistence: pass `false`
  storage: AsyncStorage,
})

const notesStore = createStarfishStore({
  name: "notes",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/notes",
    pushPath: "/push/users/abc/notes",
    encryptionSecret: "user-secret",
    encryptionSalt: "user-abc",
  }),
})
```

Each store exposes the following state and actions:

| Field | Type | Description |
|-------|------|-------------|
| `data` | `Record<string, unknown>` | Current local data snapshot |
| `syncing` | `boolean` | Whether a sync operation is in progress |
| `online` | `boolean` | Whether the device is considered online |
| `dirty` | `boolean` | Whether local data has un-pushed changes |
| `error` | `string \| null` | Last sync error message |
| `pull()` | `() => Promise<void>` | Pull remote state and merge into local |
| `set(modifier)` | `(fn) => void` | Optimistic local write — instant, no network roundtrip |
| `restore(data)` | `(data) => void` | Update data without marking dirty or triggering flush |
| `flush()` | `() => Promise<void>` | Push pending local changes to the server |
| `setOnline(online)` | `(boolean) => void` | Update connectivity; auto-flushes when going online |

#### React hooks

The `./zustand` subpath exports hooks that wrap common patterns:

```tsx
import {
  useStarfish,
  useStarfishData,
  useSyncStatus,
  useConnectivity,
  useCrossTabSync,
  useLastSynced,
  useSyncInit,
  aggregateSyncStatus,
} from "@drakkar.software/starfish-client/zustand"
```

| Hook | Returns | Description |
|------|---------|-------------|
| `useStarfish(store)` | `StarfishStore` | Full store state and actions |
| `useStarfishData(store, selector?)` | `T` | Just the data, with optional selector for fine-grained subscriptions |
| `useSyncStatus(store)` | `SyncStatus` | Derived status: `"synced"` \| `"syncing"` \| `"pending"` \| `"error"` \| `"offline"` |
| `useConnectivity(store)` | `void` | Binds browser online/offline events to `setOnline` |
| `useCrossTabSync(store, name)` | `void` | Sets up cross-tab sync with automatic cleanup |
| `useLastSynced(store)` | `string` | Human-readable label: "Just now", "15s ago", "2m ago" |
| `useSyncInit(config \| null)` | `StoreApi \| null` | Full lifecycle: create client/manager/store, pull on mount, teardown on unmount |
| `aggregateSyncStatus(statuses)` | `SyncStatus` | Combine multiple statuses (worst wins: error > syncing > pending > offline > synced) |

```tsx
function Settings() {
  const { data, syncing, pull, set } = useStarfish(settingsStore)
  useEffect(() => { pull() }, [])

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {data.theme as string}
    </button>
  )
}

// Fine-grained: only re-renders when theme changes
function ThemeBadge() {
  const theme = useStarfishData(settingsStore, (d) => d.theme as string)
  return <span>{theme}</span>
}

// Sync status indicator
function SyncBadge() {
  const status = useSyncStatus(settingsStore)
  const lastSynced = useLastSynced(settingsStore)
  return <span>{status} — {lastSynced}</span>
}
```

#### Connectivity & cross-tab sync

```tsx
function App() {
  // Binds browser online/offline events
  useConnectivity(settingsStore)
  // Syncs store across browser tabs via BroadcastChannel
  useCrossTabSync(settingsStore, "settings")

  return <Settings />
}

// React Native: use @react-native-community/netinfo instead of useConnectivity
```

#### Middleware options

**Redux DevTools** — opt-in for time-travel debugging. Import `devtools` from `zustand/middleware` and pass it as a wrapper function. All actions are labeled (`pull/start`, `pull/success`, `set`, `flush/start`, etc.):

```ts
import { devtools } from 'zustand/middleware'

const settingsStore = createStarfishStore({
  name: "settings",
  syncManager,
  devtools: (fn) => devtools(fn),
  // Or with custom options:
  // devtools: (fn) => devtools(fn, { name: "Settings Store", enabled: process.env.NODE_ENV !== "production" }),
})
```

**Immer** — pass `produce` from `immer` to enable draft-based mutations in `set()`:

```ts
import { produce } from "immer"

const settingsStore = createStarfishStore({
  name: "settings",
  syncManager,
  produce,
})

// Draft mutation style — mutate in place, immer handles immutability
settingsStore.getState().set((draft) => { draft.theme = "dark" })

// Return-new-object style still works
settingsStore.getState().set((d) => ({ ...d, theme: "dark" }))
```

**subscribeWithSelector** — always enabled. Subscribe to specific state slices with an equality function:

```ts
// Only fires when `data` changes, not when `syncing` toggles
settingsStore.subscribe(
  (state) => state.data,
  (data) => console.log("data changed:", data),
)

// With custom equality
settingsStore.subscribe(
  (state) => state.data.theme,
  (theme) => console.log("theme:", theme),
  { equalityFn: Object.is },
)
```

This gives you:
- **One store per collection** — each collection syncs, persists, and re-renders independently
- **Offline-first** — writes apply instantly to local state and persist to disk; background sync pushes to server when online
- **Automatic retry** — pending writes (`dirty: true`) flush when connectivity returns or on next app launch
- **Selectors** — subscribe to specific fields to avoid unnecessary re-renders
- **DevTools** — opt-in Redux DevTools integration with labeled actions
- **Immer** — optional draft-based mutations for simpler deeply-nested updates
- **React Native support** — pass `AsyncStorage` as `storage`; use `@react-native-community/netinfo` for connectivity detection

### State Management with Legend State

The client also ships a [Legend State](https://legendapp.com/open-source/state/) binding. Legend State uses fine-grained observables — components automatically re-render only when the exact fields they read change, with no selectors needed.

```bash
npm install @legendapp/state
```

#### Creating observables per collection

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import { createStarfishObservable } from "@drakkar.software/starfish-client/legend"

const client = new StarfishClient({ ... })

const settingsStore = createStarfishObservable({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
  }),
})

const notesStore = createStarfishObservable({
  name: "notes",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/notes",
    pushPath: "/push/users/abc/notes",
    encryptionSecret: "user-secret",
    encryptionSalt: "user-abc",
  }),
})
```

Each store returns `{ state, pull, set, flush, setOnline }`. The `state` field is a Legend State `Observable` — read values with `.get()` and subscribe by wrapping components in `observer()`.

| Field | Type | Description |
|-------|------|-------------|
| `state.data` | `Observable<Record<string, unknown>>` | Current local data snapshot |
| `state.syncing` | `Observable<boolean>` | Whether a sync operation is in progress |
| `state.online` | `Observable<boolean>` | Whether the device is considered online |
| `state.dirty` | `Observable<boolean>` | Whether local data has un-pushed changes |
| `state.error` | `Observable<string \| null>` | Last sync error message |
| `pull()` | `() => Promise<void>` | Pull remote state |
| `set(modifier)` | `(fn) => void` | Optimistic local write — instant, no network roundtrip |
| `restore(data)` | `(data) => void` | Update data without marking dirty or triggering flush |
| `flush()` | `() => Promise<void>` | Push pending local changes to the server |
| `setOnline(online)` | `(boolean) => void` | Update connectivity; auto-flushes when going online |

#### Usage in React components

Wrap components with `observer()` — any observable read inside the component automatically subscribes:

```tsx
import { observer, useSelector } from "@legendapp/state/react"

// observer() tracks all .get() calls and re-renders on change
const Settings = observer(function Settings() {
  useEffect(() => { settingsStore.pull() }, [])

  return (
    <button
      disabled={settingsStore.state.syncing.get()}
      onClick={() => settingsStore.set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {settingsStore.state.data.get().theme as string}
    </button>
  )
})

// Fine-grained: only re-renders when theme changes
function ThemeBadge() {
  const theme = useSelector(() => settingsStore.state.data.get().theme as string)
  return <span>{theme}</span>
}
```

#### Connectivity listener

```ts
useEffect(() => {
  const stores = [settingsStore, notesStore]
  const setOnline = (online: boolean) => stores.forEach((s) => s.setOnline(online))

  window.addEventListener("online", () => setOnline(true))
  window.addEventListener("offline", () => setOnline(false))
  return () => {
    window.removeEventListener("online", () => setOnline(true))
    window.removeEventListener("offline", () => setOnline(false))
  }
}, [])
```

**Immer** — pass `produce` from `immer` for draft-based mutations:

```ts
import { produce } from "immer"

const store = createStarfishObservable({ name: "settings", syncManager, produce })

store.set((draft) => { draft.theme = "dark" })
```

### Additional Client Features

The TypeScript client ships additional utilities via subpath exports:

| Subpath | Exports | Description |
|---------|---------|-------------|
| `./fetch` | `createRetryFetch`, `CircuitBreaker`, `createResilientFetch`, `createCompressedFetch` | Retry with exponential backoff, circuit breaker, gzip compression |
| `./broadcast` | `setupBroadcastSync`, `setupStorageFallback`, `setupCrossTabSync` | Cross-tab sync via BroadcastChannel or localStorage fallback |
| `./identity` | `generatePassphrase`, `deriveCredentials`, `buildInviteUrl`, `parseInviteUrl` | Passphrase-based passwordless identity and invite URLs |
| `./testing` | `createMockClient`, `createMockFetch`, `createConflictFetch` | Mock utilities for unit and integration tests |

The main entrypoint also exports:

- **Logging** — `consoleSyncLogger`, `noopSyncLogger` for `SyncManager` lifecycle events
- **Error classification** — `classifyError(err)` categorizes into `network`, `auth`, `conflict`, `rate-limited`, `server`, `client`, `unknown`
- **Schema migration** — `createMigrator(config)` for versioned migration chains with eager validation
- **Validation** — `createSchemaValidator(ajv, schema)` for pre-push Ajv validation
- **Conflict resolvers** — `createUnionMerge()`, `createSoftDeleteResolver()`, `timestampWinner()`, `pruneTombstones()`
- **Snapshot history** — `SnapshotHistory` class for undo/restore with optional localStorage persistence
- **Polling** — `startPolling()`, `startAdaptivePolling()` with network-quality adaptation and pause/resume
- **Debounced sync** — `createDebouncedSync(store, opts)` wraps a Starfish store with a debounce timer and payload size guard, preventing rapid-fire pushes and protecting against server body limits
- **Multi-store sync** — `createMultiStoreSync({ slices, version, migrations? })` serializes multiple domain stores into a single Starfish document with versioned schema migrations
- **Entitlement discovery** — `pullEntitlements(client, userId)` fetches the list of feature slugs from a user's entitlement document; returns `[]` on 404, re-throws all other errors

#### Passphrase Identity (`./identity`)

Passwordless, serverless identity derived entirely from a passphrase. One passphrase → one user.

```ts
import {
  generatePassphrase,
  deriveCredentials,
  buildInviteUrl,
  parseInviteUrl,
} from "@drakkar.software/starfish-client/identity"

// Generate a cryptographically random 12-word passphrase (96 bits of entropy)
const passphrase = generatePassphrase()
// => "game fire loud able blue sold east rock loop dark hunt calm"

// Deterministically derive auth + encryption credentials
const creds = await deriveCredentials(passphrase)
// => {
//   authToken: "a3f8...",      // 64-char hex — use as Bearer token
//   userId: "a3f8c2d1e4b0...", // 16-char hex — use in collection paths
//   encryptionSecret: "...",   // pass to SyncManager as encryptionSecret
//   encryptionSalt: "...",     // pass to SyncManager as encryptionSalt (= userId)
// }

// Wire to StarfishClient + SyncManager
const client = new StarfishClient({
  baseUrl: serverUrl,
  auth: () => ({ Authorization: `Bearer ${creds.authToken}` }),
})

const syncManager = new SyncManager({
  client,
  pullPath: `/pull/${creds.userId}/wedding`,
  pushPath: `/push/${creds.userId}/wedding`,
  encryptionSecret: creds.encryptionSecret,
  encryptionSalt: creds.encryptionSalt,
})

// Encode an invite link — share via QR code, link, or any channel
const inviteUrl = buildInviteUrl("myapp://join", { name: "Alice & Bob", p: passphrase })

// On the receiving device: parse the invite
const payload = parseInviteUrl(inviteUrl)
// => { name: "Alice & Bob", p: "game fire loud able ..." }
// Derive the same credentials and pull the synced data
```

Sharing the passphrase (via invite URL or QR code) grants full read/write access on any device — no user database, no registration, no sessions required.

#### Debounced Sync (`createDebouncedSync`)

Coalesces rapid mutations into a single push and guards against oversized payloads:

```ts
import { createDebouncedSync } from "@drakkar.software/starfish-client"

const { notify, cancel } = createDebouncedSync(starfishStore, {
  delayMs: 2000,                        // default: 2000ms
  warnBytes: 900 * 1024,                // default: 900 KB — log a warning
  maxBytes: 1024 * 1024,                // default: 1 MB — block push, log error
  serialize: () => buildSyncDocument(), // optional: snapshot domain stores before push
  onSizeWarning: (bytes) => showToast(`Payload ${bytes} bytes, approaching limit`),
  onSizeExceeded: (bytes) => showError(`Payload too large: ${bytes} bytes`),
})

// Call on every domain store mutation — timer resets each time
taskStore.subscribe(() => notify())
settingsStore.subscribe(() => notify())

// Cancel on unmount / teardown
onCleanup(() => cancel())
```

#### Multi-Store Sync (`createMultiStoreSync`)

Serializes multiple domain stores into a single Starfish document with versioned migrations:

```ts
import { createMultiStoreSync } from "@drakkar.software/starfish-client"

const multiSync = createMultiStoreSync({
  slices: {
    tasks: {
      serialize: () => taskStore.getState().tasks,
      restore: (tasks) => taskStore.setState({ tasks }),
    },
    settings: {
      serialize: () => settingsStore.getState().settings,
      restore: (settings) => settingsStore.setState({ settings }),
    },
  },
  version: 2,
  migrations: {
    // Upgrade documents from version 1 → 2
    1: (data) => ({ ...data, settings: { ...(data.settings as object), darkMode: false } }),
  },
})

// Push: snapshot all domain stores → push to Starfish
starfishStore.getState().set(() => multiSync.serialize())

// Restore: when remote data arrives, restore all domain stores
createStarfishStore({
  name: "app",
  syncManager,
  onRemoteUpdate: (doc) => multiSync.restore(doc as BackupDocument),
})
```

#### Vanilla Sync Status (`subscribeSyncStatus`)

Subscribe to sync status changes outside of React — works in React Native, Node.js, or anywhere hooks are unavailable:

```ts
import { subscribeSyncStatus } from "@drakkar.software/starfish-client/zustand"

// Fires immediately with current status, then on every change
const unsub = subscribeSyncStatus(store, (status) => {
  // status: "synced" | "syncing" | "pending" | "error" | "offline"
  updateStatusBar(status)
})

// Stop listening
unsub()
```

#### Store-less Debounced Push (`createDebouncedPush`)

For one-way publishing workflows (public pages, derived snapshots) where you push directly via `SyncManager` without a Zustand store:

```ts
import { createDebouncedPush } from "@drakkar.software/starfish-client"

const syncManager = new SyncManager({ client, pullPath, pushPath })

const { notify, cancel } = createDebouncedPush(syncManager, {
  serialize: () => buildPublicPageDocument(),  // called at push time
  onError: (err) => console.warn("Push failed:", err),
})

// Call after every relevant store mutation:
planningStore.subscribe(() => notify())

// Teardown:
cancel()
```

Includes the same payload size guard as `createDebouncedSync` (warn at 900 KB, block at 1 MB).

#### React Native Lifecycle (`createMobileLifecycle`)

Wires React Native `AppState` and `NetInfo` events to a Starfish store. Uses dependency injection — no `react-native` import in this package:

```ts
import { AppState } from "react-native"
import NetInfo from "@react-native-community/netinfo"
import { createMobileLifecycle } from "@drakkar.software/starfish-client"

// Call once after the store is created:
const cleanup = createMobileLifecycle(
  store,
  { appState: AppState, netInfo: NetInfo },
)

// In a React component root (e.g. _layout.tsx):
useEffect(() => cleanup, [])
```

- **Background** → flushes dirty data before the OS suspends the app
- **Foreground** → pulls remote changes (only if online and not already syncing)
- **NetInfo** → forwards connectivity changes to `store.getState().setOnline()`

`netInfo` is optional. Both behaviors can be disabled individually via `{ pullOnForeground: false, flushOnBackground: false }`.

```ts
import { createRetryFetch, createResilientFetch } from "@drakkar.software/starfish-client/fetch"
import { setupCrossTabSync } from "@drakkar.software/starfish-client/broadcast"
import { createMockClient } from "@drakkar.software/starfish-client/testing"
import {
  consoleSyncLogger,
  createMigrator,
  createUnionMerge,
  classifyError,
  SnapshotHistory,
  startPolling,
} from "@drakkar.software/starfish-client"
```

See the [CHANGELOG](CHANGELOG.md) for full details.

## Project Structure

```
starfish/
├── packages/
│   ├── python/
│   │   ├── protocol/      # Shared protocol primitives (hash, merge, crypto, types)
│   │   ├── server/        # Python server (FastAPI router, S3 storage, encryption, config)
│   │   └── client/        # Python client SDK (httpx + cryptography)
│   └── ts/
│       ├── protocol/      # Shared protocol primitives (hash, merge, crypto, types)
│       ├── server/        # TypeScript server (Hono router, encryption, config, CF Workers)
│       └── client/        # TypeScript client SDK + Zustand/Legend bindings
├── tests/
│   └── test-vectors/      # Cross-language hash/crypto/protocol test vectors
├── package.json           # pnpm workspace root
└── pnpm-workspace.yaml
```

## Development

```bash
pnpm install
pnpm test          # run all TS tests (unit + e2e)
pnpm test:watch    # run tests in watch mode
pnpm typecheck     # typecheck all TS packages
pnpm build         # build all TS packages

# Python protocol
cd packages/python/protocol
uv venv && uv pip install -e ".[dev]"
pytest -v

# Python server
cd packages/python/server
uv venv && uv pip install -e ".[dev]"
pytest -v

# Python client
cd packages/python/client
uv venv && uv pip install -e ".[dev]"
pytest -v
```

### Testing

TypeScript tests use [Vitest](https://vitest.dev/). Python tests use [pytest](https://docs.pytest.org/).

The TypeScript client has 259 tests across 23 test files covering sync, crypto, bindings, React hooks, broadcast, retry/circuit breaker, resolvers, migration, validation, polling, history, dedup, export, metrics, Suspense, and more. The TypeScript server has 149 tests across 17 test files covering config, protocol, encryption, router, queue, replica, storage, middleware (CORS, security headers, timeout), ETag, batch pull, field permissions, audit logging, TTL, OpenAPI, and lifecycle. The Python server has 246 tests.

Cross-language test vectors in `tests/test-vectors/` ensure identical behavior across all TypeScript and Python implementations:
- `crypto.json` / `hash.json` — encryption and hashing parity
- `protocol-push.json` / `protocol-timestamps.json` — protocol-level push, pull, and timestamp computation parity
- `http-errors.json` — error response contract (status codes and messages)

## Advanced Setup

### Storage backends

Both Python and TypeScript servers provide the same set of storage backends.

**`MemoryObjectStore`** — pure in-memory store, zero configuration. Data is lost when the process exits.

```python
# Python
from starfish_server import MemoryObjectStore

store = MemoryObjectStore()           # global — shared across all default instances
store = MemoryObjectStore(data={})    # isolated — independent empty dict (for tests)
```

```ts
// TypeScript
import { MemoryObjectStore } from "@drakkar.software/starfish-server"

const store = new MemoryObjectStore()             // global — shared across instances
const store = new MemoryObjectStore(new Map())    // isolated (for tests)
```

**`CustomObjectStore`** — backed entirely by your own callback functions. Bridge Starfish to any external system (database, remote API, custom cache) without implementing the full storage interface. Callbacks may be sync or async; omitted callbacks are safe no-ops.

```python
# Python
from starfish_server import CustomObjectStore

store = CustomObjectStore(
    on_get=lambda key: data.get(key),
    on_put=lambda key, body: data.update({key: body}),
    on_list=lambda prefix, start_after, limit: sorted(
        k for k in data if k.startswith(prefix)
    ),
    on_delete=lambda key: data.pop(key, None),
)
```

```ts
// TypeScript
import { CustomObjectStore } from "@drakkar.software/starfish-server"

const store = new CustomObjectStore({
  onGet: (key) => data.get(key) ?? null,
  onPut: (key, body) => { data.set(key, body) },
  onList: (prefix) => [...data.keys()].filter(k => k.startsWith(prefix)).sort(),
  onDelete: (key) => { data.delete(key) },
})
```

**`FilesystemObjectStore`** — files on disk, atomic writes. Good for single-node deployments.

```python
# Python
from starfish_server import FilesystemObjectStore, FilesystemStorageOptions

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))
```

```ts
// TypeScript (Node.js only — subpath export)
import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"

const store = new FilesystemObjectStore({ baseDir: "./data" })
```

**`S3ObjectStore`** — S3-compatible object storage (AWS S3, Cloudflare R2, MinIO). Python requires `pip install starfish-server[s3]`; TypeScript requires `npm install @aws-sdk/client-s3`.

```python
# Python
from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions

store = S3ObjectStore(S3StorageOptions(
    access_key_id="...",
    secret_access_key="...",
    endpoint="https://s3.amazonaws.com",
    bucket="my-bucket",
))
```

```ts
// TypeScript (subpath export — requires @aws-sdk/client-s3 peer dep)
import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"

const store = new S3ObjectStore({
  accessKeyId: process.env.S3_ACCESS_KEY_ID!,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY!,
  endpoint: "https://s3.amazonaws.com",
  bucket: "my-bucket",
})
// Call store.destroy() on shutdown to release HTTP connections
```

### Delegated encryption

With `"delegated"` mode, the server never encrypts or decrypts — it stores whatever the client sends as-is. The user generates a secret key and encrypts client-side using their public key as salt. They can share the secret + public key with a third party to grant decryption access.

> **The salt must be deterministic across all devices.** Since HKDF derives the encryption key from both `secret` and `salt`, every device that needs to read or write the same data must use the exact same values for both. Never use a value that varies per device (e.g., a local database ID, random UUID, or device identifier) as the salt — this will cause each device to derive a different key, making cross-device sync silently fail (data is encrypted with one key and cannot be decrypted with another).
>
> Safe salt choices:
> - A value derived from the secret itself: `hash(secret).slice(0, N)`
> - A shared public key or user identifier that is the same on all devices
> - A constant string (if only one user accesses the data)

```json
{
  "name": "vault",
  "storagePath": "users/{identity}/vault",
  "readRoles": ["self"],
  "writeRoles": ["self"],
  "encryption": "delegated",
  "maxBodyBytes": 65536
}
```

```python
from starfish_sdk import SyncManager

sync = SyncManager(
    client,
    pull_path="/pull/users/abc/vault",
    push_path="/push/users/abc/vault",
    encryption_secret="my-secret-key",       # user-generated secret
    encryption_salt="my-public-key-abc123",   # user's public key (same on all devices)
)

await sync.push({"balance": 1000})
await sync.pull()  # returns decrypted data
```

```ts
// A third party decrypts using the credentials shared by the user
const adminSync = new SyncManager({
  client,
  pullPath: "/pull/users/abc/vault",
  pushPath: "/push/users/abc/vault",
  encryptionSecret: "my-secret-key",
  encryptionSalt: "my-public-key-abc123",
})
await adminSync.pull()
```

The server stores only the encrypted blob. Anyone with the correct secret + salt can decrypt client-side.

### Bundles

Collections with the same `bundle` value share a storage path and expose a combined pull endpoint:

```ts
{ name: "settings", storagePath: "users/{identity}", bundle: "user-data", ... },
{ name: "favorites", storagePath: "users/{identity}", bundle: "user-data", ... },
```

`GET /pull/users/:identity` returns all bundled collections in a single response. Push remains per-collection.

### Queue (change events)

Publish a lightweight change event to a message queue after every successful push. Built-in backends: `MemoryQueue` (testing), `CustomQueue` (callback-based), `NatsQueue` (Python/NATS — `pip install starfish-server[nats]`).

Queue errors never surface to clients — they are logged and the push response is returned normally.

> Full reference: [`docs/ts/server/queue.md`](docs/ts/server/queue.md)

#### QueueConfig

| Field | Type | Default | Description |
|---|---|---|---|
| `topic` | `string` | collection name | Topic / NATS subject to publish to |
| `includeParams` | `boolean` | `false` | Include resolved path params in the payload |
| `includeBody` | `boolean?` | `false` | Include push request data in the payload (JSON collections only) |

Pass `true` as a shorthand for defaults (topic = collection name, `includeParams: false`, `includeBody: false`). Pass `false` or omit to disable.

### List Endpoint

Set `listable: true` on a collection to expose a `GET /list/...` endpoint that returns the existing document keys under the collection's prefix. Clients use this to discover which documents exist — for example, which days have chat messages for a group.

The route drops the last path parameter from `storagePath` and enumerates its values:

| `storagePath` | List route | Returns |
|---|---|---|
| `chats/{groupId}/{day}` | `GET /list/chats/:groupId` | day values |
| `notes/{userId}` | `GET /list/notes` | userId values |

```ts
// TypeScript
{ name: "chat", storagePath: "chats/{groupId}/{day}", readRoles: ["group-member"], /* ... */, listable: true }
```

```python
# Python
CollectionConfig(name="chat", storage_path="chats/{groupId}/{day}", read_roles=["group-member"], ..., listable=True)
```

Response: `{ "items": ["2026-04-13", "2026-04-12"], "hasMore": false }`. Pagination: `?limit=N` (default 100, max 1000) and `?after=<item>`.

> Full reference: [`docs/ts/server/list-endpoint.md`](docs/ts/server/list-endpoint.md)

---

### Group-Based Access Control

Use `createGroupRoleEnricher` / `create_group_role_enricher` to grant access based on a member list stored in another Starfish collection. The enricher reads a membership document from the ObjectStore and grants a role (default `"group-member"`) to any user whose identity appears in the list.

```ts
// TypeScript
import { createGroupRoleEnricher } from "@drakkar.software/starfish-server"

const router = createSyncRouter({
  store, config,
  roleResolver: async (c) => ({ identity: await getUserId(c), roles: [] }),
  roleEnricher: createGroupRoleEnricher({
    store,
    membersPath: "groups/{groupId}/members",  // storagePath of the members doc
    groupParam: "groupId",                     // which URL param identifies the group
    // membersField: "members" (default)
    // role: "group-member" (default)
    // cacheTtlMs: 60000 (default, 1 minute)
  }),
})
```

```python
# Python
from starfish_server import create_group_role_enricher, GroupRoleEnricherOptions

enricher = create_group_role_enricher(GroupRoleEnricherOptions(
    store=store,
    members_path="groups/{groupId}/members",
    group_param="groupId",
))
router = create_sync_router(SyncRouterOptions(..., role_enricher=enricher))
```

Members document (standard Starfish push):
```json
{ "members": ["alice", "bob", "charlie"] }
```

**Group candidacy** — users can apply to join a group. Set `candidacyPath` on the enricher and add `candidacyEnabled: true` to the members document. Applicants push `{ status: "pending", message: "..." }` to a candidacy collection (gated by `"self"` role). Pending applicants receive `"group-candidate"` (configurable); admins accept or deny by pushing `{ status: "accepted" }` / `{ status: "denied" }` and manually adding accepted users to the members document.

```ts
createGroupRoleEnricher({
  store,
  membersPath: "groups/{groupId}/members",
  groupParam: "groupId",
  candidacyPath: "groups/{groupId}/candidacies/{identity}",
  // candidacyRole: "group-candidate" (default)
})
```

> Full reference: [`docs/ts/server/group-access.md`](docs/ts/server/group-access.md)

---

### Entitlement-Based Access Control

Use `createEntitlementRoleEnricher` / `create_entitlement_role_enricher` to gate collections behind per-user feature slugs. The enricher reads a per-user entitlement document from the ObjectStore and grants roles of the form `"entitlement:<slug>"`. Collections declare which slugs unlock access in `readRoles`/`writeRoles`.

```ts
// TypeScript
import { createEntitlementRoleEnricher, composeEnrichers } from "@drakkar.software/starfish-server"

const entitlementEnricher = createEntitlementRoleEnricher({ store })
// Combine with other enrichers using composeEnrichers:
const roleEnricher = composeEnrichers(groupEnricher, entitlementEnricher)

const router = createSyncRouter({
  store, config,
  roleResolver: async (c) => ({ identity: await getUserId(c), roles: [] }),
  roleEnricher,
})
```

```python
# Python
from starfish_server import create_entitlement_role_enricher, EntitlementRoleEnricherOptions, compose_enrichers

entitlement_enricher = create_entitlement_role_enricher(EntitlementRoleEnricherOptions(store=store))
role_enricher = compose_enrichers(group_enricher, entitlement_enricher)
router = create_sync_router(SyncRouterOptions(..., role_enricher=role_enricher))
```

Entitlement collection config (admin writes, user reads):
```ts
{ name: "entitlements", storagePath: "users/{identity}/entitlements",
  readRoles: ["self"], writeRoles: ["admin"],
  encryption: "none", maxBodyBytes: 4096, allowedMimeTypes: ["application/json"] }
```

Entitlement document (admin pushes):
```json
{ "features": ["premium-package-1", "paid-cloud-sync"] }
```

Gated collection:
```ts
{ name: "premium-content", storagePath: "premium/{resource}",
  readRoles: ["entitlement:premium-package-1"], writeRoles: ["admin"] }
```

> Full reference: [`docs/ts/server/entitlements.md`](docs/ts/server/entitlements.md)

---

#### Queue-only collections

Set `queueOnly: true` (`queue_only=True` in Python) on a collection to skip storage entirely. Pushes are accepted and return a `{hash, timestamp}`, but nothing is stored. Pull always returns empty. `baseHash` conflict detection is disabled.

Use for event-only streams where only the queue consumer matters:

```ts
// TypeScript
{ name: "events", storagePath: "events/{eventId}", /* ... */, queueOnly: true, queue: { topic: "analytics.events" } }
```

```python
# Python
CollectionConfig(name="events", storage_path="events/{eventId}", ..., queue_only=True, queue=QueueConfig(topic="analytics.events"))
```

#### Collection config

```ts
// TypeScript
{
  name: "posts",
  storagePath: "posts/{postId}",
  // ...
  queue: true,  // topic = "posts", includeParams = false, includeBody = false
  // Or:
  // queue: { topic: "data.posts.changed", includeParams: true, includeBody: true },
}
```

```python
# Python
CollectionConfig(
    name="posts",
    storage_path="posts/{postId}",
    # ...
    queue=True,  # topic = "posts", include_params = False, include_body = False
    # Or:
    # queue=QueueConfig(topic="data.posts.changed", include_params=True, include_body=True),
)
```

#### Server setup

```ts
// TypeScript — CustomQueue (any backend via callback)
import { CustomQueue } from "@drakkar.software/starfish-server"

const queue = new CustomQueue({
  onPublish: async (subject, payload) => {
    await natsClient.publish(subject, payload)
  },
})

const sync = createSyncRouter({ store, config, roleResolver, queue })
```

```python
# Python — NatsQueue
from starfish_server.queue.nats import NatsQueue, NatsQueueOptions

queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))

sync_router = create_sync_router(SyncRouterOptions(
    store=store, config=config, role_resolver=role_resolver, queue=queue,
))

@asynccontextmanager
async def lifespan(app):
    await queue.connect()
    yield
    await queue.close()

app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
```

#### Event payload

```json
{
  "collection": "posts",
  "hash": "abc123...",
  "timestamp": 1712345678000
}
```

`params` is added when `includeParams: true`:

```json
{
  "collection": "posts",
  "hash": "abc123...",
  "timestamp": 1712345678000,
  "params": { "postId": "abc" }
}
```

`body` is added when `includeBody: true` (JSON collections only):

```json
{
  "collection": "posts",
  "hash": "abc123...",
  "timestamp": 1712345678000,
  "body": { "title": "Hello world", "published": true }
}
```

The `QueueMessage` type is exported for use in consumers:

```ts
import type { QueueMessage } from "@drakkar.software/starfish-server"
```

```python
from starfish_server import QueueMessage
```

### Config endpoint

`GET /config` lets clients discover server capabilities at runtime — collection names, size limits, encryption modes, supported MIME types, and public keys for client-side encryption.

Enable it via `configEndpoint` / `config_endpoint` on the router options:

```ts
// TypeScript
const sync = createSyncRouter({
  store, config, roleResolver,
  configEndpoint: { auth: "public" },       // or "role-filtered"
})
```

```python
# Python
sync_router = create_sync_router(SyncRouterOptions(
    store=store, config=config, role_resolver=role_resolver,
    config_endpoint=ConfigEndpointOptions(auth="public"),
))
```

**Auth modes:** `"public"` — no auth check, all collections returned. `"role-filtered"` — caller sees only collections matching their roles.

**publicKey field** — add a `publicKey` string to any collection config to expose a base64-encoded public key through `/config`. Clients can use it to encrypt data before pushing.

Fetch from the client:

```ts
import { fetchServerConfig } from "@drakkar.software/starfish-client"
const config = await fetchServerConfig("https://api.example.com/v1")
// config.collections[0].publicKey, .maxBodyBytes, .queueOnly, …
```

```python
from starfish_sdk import fetch_server_config
config = await fetch_server_config("https://api.example.com/v1")
# config.collections[0].public_key, .max_body_bytes, .queue_only, …
```

> Full reference: [`docs/ts/server/config-endpoint.md`](docs/ts/server/config-endpoint.md)

### Replicas

The replica system lets you run multiple Starfish servers that stay in sync. A **primary** server holds the source of truth; **replicas** pull from it and serve reads locally.

#### Collection config

Add a `remote` block to any collection to make it replicated:

```python
CollectionConfig(
    name="posts",
    storage_path="posts/{postId}",
    read_roles=["public"],
    write_roles=["admin"],
    encryption="none",
    max_body_bytes=65536,
    remote=RemoteConfig(
        url="https://primary.example.com/v1",
        pull_path="/pull/posts/{postId}",
        interval_ms=30_000,           # poll every 30s
        write_mode="pull_only",       # clients can't push to replica
        sync_triggers=["scheduled"],
        headers={"Authorization": "Bearer replica-token"},
    ),
)
```

**Write modes**

| Mode | Client reads | Client writes | Syncs from primary |
|---|---|---|---|
| `pull_only` | ✓ | ✗ (405) | ✓ replace |
| `push_through` | ✓ | → forwarded to primary | ✓ replace |
| `bidirectional` | ✓ | ✓ local + merged | ✓ remote-wins deep merge |
| `push_only` | ✗ (405) | ✓ local only | ✗ |

**Sync triggers**

| Trigger | When |
|---|---|
| `scheduled` | Every `interval_ms` in the background |
| `on_pull` | Before each client `GET /pull/…` (respects `on_pull_min_interval_ms` cooldown) |

#### Replica server

```python
# Python
from starfish_server import ReplicaManager

replica_manager = ReplicaManager(store, config.collections)

sync_router = create_sync_router(SyncRouterOptions(
    store=store, config=config,
    role_resolver=role_resolver, replica_manager=replica_manager,
))

@asynccontextmanager
async def lifespan(app):
    await replica_manager.start()
    yield
    await replica_manager.stop()

app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
```

```ts
// TypeScript
import { ReplicaManager, createSyncRouter } from "@drakkar.software/starfish-server"

const replicaManager = new ReplicaManager(store, config.collections)

const sync = createSyncRouter({
  store, config, roleResolver, replicaManager,
})

// Node.js: start/stop background sync
replicaManager.start()
process.on("SIGTERM", () => replicaManager.stop())

// CF Workers: use syncNow()/syncAll() from Cron Triggers instead
```

## Deployment

### Ansible

An Ansible role is included at `infra/ansible/roles/starfish`. It installs the runtime, creates a dedicated system user, deploys a templated server and `config.json`, and registers a systemd service.

```bash
# Deploy a Python server
ansible-playbook infra/ansible/playbooks/deploy.yml \
  -i infra/ansible/inventory/hosts.example

# Switch to the TypeScript/Hono variant
ansible-playbook infra/ansible/playbooks/deploy.yml \
  -i infra/ansible/inventory/hosts.example \
  -e starfish_variant=typescript
```

Configure collections and namespaces entirely from Ansible variables — no server code changes needed:

```yaml
# group_vars/starfish_servers.yml
starfish_variant: python
starfish_port: 8000
starfish_encryption_secret: "{{ vault_starfish_encryption_secret }}"

starfish_config_collections:
  - name: posts
    storagePath: "posts/{postId}"
    readRoles: [public]
    writeRoles: [admin]
    encryption: none
    maxBodyBytes: 65536

starfish_config_namespaces:
  acme:
    collections:
      - name: settings
        storagePath: "acme/users/{identity}/settings"
        readRoles: [self]
        writeRoles: [self]
        encryption: none
        maxBodyBytes: 65536
```

See `infra/ansible/playbooks/deploy.yml` for a full example with namespaces and vault usage.
