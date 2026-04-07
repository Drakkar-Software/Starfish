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
    "https://api.example.com/v1",
    auth=my_auth_provider,
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

**Redux DevTools** — opt-in with `devtools: true` for time-travel debugging. All actions are labeled (`pull/start`, `pull/success`, `set`, `flush/start`, etc.):

```ts
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager,
  devtools: true,
  // Or with custom options:
  // devtools: { name: "Settings Store", enabled: process.env.NODE_ENV !== "production" },
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
| `./testing` | `createMockClient`, `createMockFetch`, `createConflictFetch` | Mock utilities for unit and integration tests |

The main entrypoint also exports:

- **Logging** — `consoleSyncLogger`, `noopSyncLogger` for `SyncManager` lifecycle events
- **Error classification** — `classifyError(err)` categorizes into `network`, `auth`, `conflict`, `rate-limited`, `server`, `client`, `unknown`
- **Schema migration** — `createMigrator(config)` for versioned migration chains with eager validation
- **Validation** — `createSchemaValidator(ajv, schema)` for pre-push Ajv validation
- **Conflict resolvers** — `createUnionMerge()`, `createSoftDeleteResolver()`, `timestampWinner()`, `pruneTombstones()`
- **Snapshot history** — `SnapshotHistory` class for undo/restore with optional localStorage persistence
- **Polling** — `startPolling()`, `startAdaptivePolling()` with network-quality adaptation and pause/resume

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

The TypeScript client has 218 tests across 16 test files covering sync, crypto, bindings, React hooks, broadcast, retry/circuit breaker, resolvers, migration, validation, polling, history, and more. The TypeScript server has 92 tests covering config, protocol, encryption, router, queue, replica, and storage.

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

**`S3ObjectStore`** (Python only) — S3-compatible object storage (AWS S3, Cloudflare R2, MinIO). Requires `pip install starfish-server[s3]`.

```python
from starfish_server.storage.s3 import S3ObjectStore, S3StorageOptions

store = S3ObjectStore(S3StorageOptions(
    access_key_id="...",
    secret_access_key="...",
    endpoint="https://s3.amazonaws.com",
    bucket="my-bucket",
))
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

Publish data-change events to a message queue after every successful push. The queue system uses the same abstraction pattern as storage: an abstract base class with pluggable implementations.

Built-in backends: `MemoryQueue` (testing), `CustomQueue` (callback-based), `NatsQueue` (NATS). Install NATS support: `pip install starfish-server[nats]`.

#### Collection config

Enable queue events per collection:

```python
CollectionConfig(
    name="posts",
    storage_path="posts/{postId}",
    read_roles=["public"],
    write_roles=["admin"],
    encryption="none",
    max_body_bytes=65536,
    queue=True,  # publish to topic "posts" (= collection name)
    # Or with custom settings:
    # queue=QueueConfig(topic="data.posts.changed", include_params=True),
)
```

#### Server setup

```python
from contextlib import asynccontextmanager
from starfish_server.queue.nats import NatsQueue, NatsQueueOptions

queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))

sync_router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    queue=queue,
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
  "timestamp": 1712345678000,
  "params": {"postId": "abc"}
}
```

`params` is only included when `includeParams: true` in the queue config.

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
