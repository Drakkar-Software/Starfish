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

### Client SDKs

| Package | Language | Description |
|---|---|---|
| `@starfish/client` | TypeScript | Browser, Node.js & React Native client with sync manager |
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

Configuration can be loaded from multiple sources (Python server):

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

Use `role_enricher` for context-dependent roles (e.g. resource ownership):

```python
async def role_enricher(auth, params):
    if params.get("postId") and await is_owner(auth.identity, params["postId"]):
        return ["owner"]
    return []

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    role_enricher=role_enricher,
))
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
import { StarfishClient, SyncManager } from "@starfish/client"

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
import { StarfishClient, SyncManager } from "@starfish/client"

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

You can also use the encryptor standalone:

```ts
import { createEncryptor } from "@starfish/client"

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
import { configurePlatform } from "@starfish/client"
import QuickCrypto from "react-native-quick-crypto"

configurePlatform({
  crypto: QuickCrypto,
  base64: {
    encode: (data) => Buffer.from(data).toString("base64"),
    decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

// Now use the SDK normally
import { SyncManager } from "@starfish/client"
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
import { StarfishClient, SyncManager } from "@starfish/client"
import { createStarfishStore } from "@starfish/client/zustand"
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
| `flush()` | `() => Promise<void>` | Push pending local changes to the server |
| `setOnline(online)` | `(boolean) => void` | Update connectivity; auto-flushes when going online |

#### Usage in React components

```tsx
import { useStore } from "zustand"

function Settings() {
  const { data, syncing, pull, set } = useStore(settingsStore)
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

function Notes() {
  const { data, pull, set } = useStore(notesStore)
  useEffect(() => { pull() }, [])

  const notes = (data.items ?? []) as string[]
  return (
    <>
      <ul>{notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
      <button onClick={() => set((d) => ({
        ...d,
        items: [...(d.items as string[] ?? []), "new note"],
      }))}>
        Add note
      </button>
    </>
  )
}

// Selectors — subscribe to specific fields to avoid re-renders
function ThemeBadge() {
  const theme = useStore(settingsStore, (s) => s.data.theme)
  return <span>{theme as string}</span>
}
```

#### Connectivity listener

```ts
// Browser
useEffect(() => {
  const stores = [settingsStore, notesStore]
  const on = () => stores.forEach((s) => s.getState().setOnline(true))
  const off = () => stores.forEach((s) => s.getState().setOnline(false))
  window.addEventListener("online", on)
  window.addEventListener("offline", off)
  return () => {
    window.removeEventListener("online", on)
    window.removeEventListener("offline", off)
  }
}, [])

// React Native: use @react-native-community/netinfo instead
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
import { StarfishClient, SyncManager } from "@starfish/client"
import { createStarfishObservable } from "@starfish/client/legend"

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
│       └── client/        # TypeScript client SDK + Zustand binding
├── tests/
│   └── test-vectors/      # Cross-language hash/crypto test vectors
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

The TypeScript client includes end-to-end tests that wire a real `StarfishClient` + `SyncManager` + Zustand store against an in-memory server backend — no mocks.

Cross-language test vectors in `tests/test-vectors/` ensure `stableStringify` and `computeHash` produce identical results across all TypeScript and Python implementations.

## Advanced Setup

### Storage backends

Four storage backends are provided out of the box.

**`MemoryObjectStore`** — pure in-memory dict, zero configuration. All instances share the same module-level global dict by default, so you can use `MemoryObjectStore()` anywhere in your app without dependency injection. Data is lost when the process exits.

```python
from starfish_server import MemoryObjectStore

store = MemoryObjectStore()           # global — shared across all default instances
store = MemoryObjectStore(data={})    # isolated — independent empty dict (for tests)
```

**`CustomObjectStore`** — backed entirely by your own callback functions. Bridge Starfish to any external system (database, remote API, custom cache) without implementing the full storage interface. Callbacks may be sync or async; omitted callbacks are safe no-ops.

```python
from starfish_server import CustomObjectStore

data: dict[str, str] = {}

store = CustomObjectStore(
    on_get=lambda key: data.get(key),
    on_put=lambda key, body: data.update({key: body}),
    on_list=lambda prefix, start_after, limit: sorted(
        k for k in data if k.startswith(prefix)
    ),
    on_delete=lambda key: data.pop(key, None),
)
```

**`FilesystemObjectStore`** — files on disk, atomic writes, thread-pool I/O. Good for single-node deployments.

```python
from starfish_server import FilesystemObjectStore, FilesystemStorageOptions

store = FilesystemObjectStore(FilesystemStorageOptions(base_dir="./data"))
```

**`S3ObjectStore`** — S3-compatible object storage (AWS S3, Cloudflare R2, MinIO). Requires `pip install starfish-server[s3]`.

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
    encryption_salt="my-public-key-abc123",   # user's public key
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
        sync_triggers=["scheduled", "webhook"],
        webhook_secret="shared-hmac-secret",
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
| `webhook` | When the primary POSTs to `/replica/notify` |
| `on_pull` | Before each client `GET /pull/…` (respects `on_pull_min_interval_ms` cooldown) |

#### Primary server

```python
from contextlib import asynccontextmanager
from starfish_server import NotificationPublisher, SubscriptionStore
from starfish_server.replica import create_replica_router

subscription_store = SubscriptionStore(store)
notification_publisher = NotificationPublisher(
    subscription_store,
    webhook_secret="shared-hmac-secret",
)

sync_router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    notification_publisher=notification_publisher,  # notifies replicas on write
))

replica_router = create_replica_router(
    subscription_store=subscription_store,
    role_resolver=role_resolver,
    subscribe_role="admin",  # role required to register a replica
)

@asynccontextmanager
async def lifespan(app):
    yield
    await notification_publisher.close()

app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
app.include_router(replica_router, prefix="/v1")
```

#### Replica server

```python
from starfish_server import ReplicaManager
from starfish_server.replica import create_replica_router

replica_manager = ReplicaManager(
    store,
    config.collections,
    self_base_url="https://replica.example.com/v1",  # so the primary can push back
)

sync_router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    replica_manager=replica_manager,  # triggers on_pull syncs
))

replica_router = create_replica_router(
    replica_manager=replica_manager,
    collections=config.collections,  # used to verify webhook signatures
)

@asynccontextmanager
async def lifespan(app):
    await replica_manager.start()   # starts background tasks + subscribes to primary
    yield
    await replica_manager.stop()

app = FastAPI(lifespan=lifespan)
app.include_router(sync_router, prefix="/v1")
app.include_router(replica_router, prefix="/v1")
```

#### Webhook security

When `webhook_secret` is configured, the primary signs every notification with HMAC-SHA256 and the replica verifies it before syncing:

```
X-Starfish-Signature: sha256=<hmac-sha256-hex>
```

The same secret must be set on both sides. Notifications with a missing or invalid signature are rejected with `401`.
