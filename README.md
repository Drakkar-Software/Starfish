<p align="center">
  <img src="logo.png" alt="Starfish" width="400" />
</p>

# Starfish

A generic document sync library. Pull/push documents with hash-based conflict detection, incremental sync via timestamps, and role-based access control.

Works with any storage backend (S3, MongoDB, in-memory) and any auth model. The server determines roles; the library enforces permissions.

**Encryption:** two modes only — `"none"` (server stores plaintext) and `"delegated"` (end-to-end AES-256-GCM, N-recipient). In `"delegated"` mode the server stores opaque ciphertext plus a plaintext per-collection **keyring document** that wraps the current Content Encryption Key (CEK) for each recipient via X25519 ECDH + HKDF + AES-GCM. The server never sees a CEK.

**Authorization:** every authenticated request carries a signed **capability certificate** (cap-cert). The cap-cert is issued by the user's root identity (derived from a passphrase) and grants a subset of `{ops, collections, paths}` to a specific device or member subject for a bounded lifetime. Each request is itself signed under the subject key, with nonce-replay protection and ±5 min clock skew.

**Identity model:** Starfish speaks **Ed25519 (sign) + X25519 (KEM)** on the wire — a single suite, no algorithm discriminator. Root identities derive from a passphrase via Argon2id → HKDF-SHA256. Users with an existing **external secp256k1 root** (e.g. a Nostr `nsec`, a Bitcoin/BIP-340 signer) can bootstrap a Starfish identity via `deriveRootIdentityFromSecp256k1Signature`: the caller signs a fixed 32-byte challenge with their external signer, and the 64-byte signature is HKDF-expanded into the Ed25519 + X25519 seeds. The secp256k1 root never appears on the wire; the resulting identity is a normal Ed25519 identity from every verifier's perspective. See [docs/ts/client/26-identity-models.md](docs/ts/client/26-identity-models.md).

> **Upgrading from 2.x?** v3 is a clean break. See [docs/migration/v2-to-v3.md](docs/migration/v2-to-v3.md).

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
from starfish_server import (
    MemoryObjectStore,
    load_config,
    create_cap_cert_role_resolver,
    create_in_memory_nonce_cache,
    create_in_memory_revocation_store,
)
from starfish_server.router import create_sync_router, SyncRouterOptions

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

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    # v3 default: validates cap-cert + per-request signature + nonce + revocation.
    role_resolver=create_cap_cert_role_resolver(
        nonce_cache=create_in_memory_nonce_cache(),
        revocation_store=create_in_memory_revocation_store(),
        allow_anonymous=True,
    ),
))

app = FastAPI()
app.include_router(router, prefix="/v1")
```

### TypeScript Server (Hono / Cloudflare Workers)

```ts
import { Hono } from "hono"
import {
  createSyncRouter,
  MemoryObjectStore,
  parseConfigJson,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
} from "@drakkar.software/starfish-server"

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
    readRoles:  ["self", "cap:read:settings"],
    writeRoles: ["self", "cap:write:settings"],
    encryption: "none",
    maxBodyBytes: 65536,
  }],
}))

const sync = createSyncRouter({
  store,
  config,
  // v3 default: validates cap-cert + per-request signature + nonce + revocation.
  // Secure by default — with no `plugins` the resolver accepts only `device`
  // caps. To accept `member` caps (sharing), wire the extension plugins:
  //   plugins: [identitiesServerPlugin, sharingServerPlugin]
  roleResolver: createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    allowAnonymous: true,
  }),
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
import { createJsonLogger } from "@drakkar.software/starfish-server"
import { createCallbackAuditLogger } from "@drakkar.software/starfish-audit"

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
  name: "invoices",                         // unique identifier
  storagePath: "users/{identity}/invoices", // document key template
  readRoles: ["self", "admin"],             // who can pull
  writeRoles: ["self"],                     // who can push
  encryption: "delegated",                  // "none" | "delegated"
  maxBodyBytes: 65536,                      // body size limit
  // keyringPath defaults to `<storagePath>/_keyring` for "delegated"
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

Two modes — and nothing in between. The server never holds any encryption key.

- **`"none"`** — stored in plaintext. Use for public data, server-managed indexes, anything that does not need confidentiality from the operator.
- **`"delegated"`** — client-side AES-256-GCM. Each collection has a plaintext **keyring document** at `<storagePath>/_keyring` (override with `keyringPath`) listing per-recipient X25519 wraps of the current Content Encryption Key (CEK). Scales to N recipients — single device, multi-device, or multi-user — under one mode. See [Multi-Recipient Delegated Encryption](docs/ts/client/23-multi-recipient-delegated.md).

## Client SDKs

All clients implement the same protocol: pull/push with hash-based conflict detection, incremental sync via checkpoints, optional E2E encryption, and automatic conflict resolution.

### TypeScript

Works in Browser, Node.js, and React Native (see [Platform Support](#platform-support)).

```ts
import {
  StarfishClient, SyncManager,
  bootstrapRootIdentity, createKeyringEncryptor,
  type Keyring,
} from "@drakkar.software/starfish-client"

// 1. Derive root identity + self-signed cap-cert from a passphrase.
const creds = await bootstrapRootIdentity(passphrase)

// 2. StarfishClient signs every request via the CapProvider.
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// 3. (Delegated only) build an encryptor from the collection's keyring.
const keyring = (await client.pull("/pull/notes/_keyring")).data as Keyring
const encryptor = await createKeyringEncryptor(keyring, {
  kemPubHex: creds.device.kemPub,
  kemPrivHex: creds.device.kemPriv,
})

// 4. Sync. `signer` attaches an Ed25519 author signature to every push.
const sync = new SyncManager({
  client,
  pullPath: `/pull/notes/${creds.userId}`,
  pushPath: `/push/notes/${creds.userId}`,
  encryptor,
  signer: {
    getSigner: async () => ({
      devEdPubHex: creds.device.edPub,
      sign: async (bytes) => ed25519Sign(creds.device.edPriv, bytes),
    }),
  },
})

await sync.pull()
await sync.push({ items: ["hello"] })
```

### Python

```python
from starfish_sdk import (
    StarfishClient, SyncManager,
    bootstrap_root_identity, create_keyring_encryptor,
)

creds = bootstrap_root_identity(passphrase)

class MyCapProvider:
    async def get_cap(self):
        return {"cap": creds.cap_cert, "dev_ed_priv_hex": creds.device["ed_priv"]}

async with StarfishClient(
    "https://api.example.com/v1",
    cap_provider=MyCapProvider(),
) as client:
    keyring = (await client.pull("/pull/notes/_keyring")).data
    encryptor = create_keyring_encryptor(
        keyring,
        {"kem_pub_hex": creds.device["kem_pub"], "kem_priv_hex": creds.device["kem_priv"]},
    )

    sync = SyncManager(
        client,
        f"/pull/notes/{creds.user_id}",
        f"/push/notes/{creds.user_id}",
        encryptor=encryptor,
    )
    await sync.pull()
    await sync.push({"items": ["hello"]})

    # Binary (blob) documents
    blob_result = await client.pull_blob("/pull/files/abc/photo.jpg")
    await client.push_blob("/push/files/abc/photo.jpg", b"...", blob_result.hash, "image/jpeg")

    # Entitlement discovery
    from starfish_entitlements import pull_entitlements
    features = await pull_entitlements(client, "alice")
    # e.g. ["premium-package-1", "paid-cloud-sync"]
```

### Cap-cert authorization

Every authenticated request carries a signed cap-cert plus a per-request Ed25519 signature. The wire shape:

| Header | Value |
|---|---|
| `Authorization` | `Cap <base64(stableStringify(cap))>` |
| `X-Starfish-Sig` | base64 Ed25519 signature over `(method, pathAndQuery, sha256(body), ts, nonce)` |
| `X-Starfish-Ts` | Unix milliseconds (±5 min server clock skew) |
| `X-Starfish-Nonce` | base64 random 16 bytes — server-side LRU prevents reuse |

Add a new device via in-person QR or a server-relay 6-digit code; grant a third party access by minting a `kind: "member"` cap-cert. See [Capability Certificates](docs/ts/client/25-capability-certs.md), [Pairing](docs/ts/client/24-pairing.md), and [Multi-Recipient Delegated Encryption](docs/ts/client/23-multi-recipient-delegated.md).

When the server (or QR/relay channel) is not fully trusted, prefer the explicit safety knobs: `assemblePairingBundle({ grantedScope })` bounds a paired device's authority instead of trusting the peer-supplied scope, `installPairingBundle(bundle, device, { expectedQrNonce })` binds the bundle to its pairing session (and the install now fully verifies the cap-cert — signature, expiry window, and `kind === "device"`), and `addCollectionRecipient` / `removeRecipient` accept a `trustedAdders` pin so a hostile server cannot substitute a keyring entry. `scopes.admin` is a **device-cap** preset (it manages the keyring); `mintMemberCap` rejects it.

### Client-Side Encryption (delegated)

In `"delegated"` mode a collection has data documents (opaque `{_encrypted, _epoch}` ciphertext) plus one **keyring document** at `<storagePath>/_keyring` (override with `keyringPath`). The keyring carries one Content Encryption Key (CEK) per epoch, wrapped separately for each recipient via per-entry ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM, signed by the granting device for audit.

Rotating the epoch (`rotateEpoch`) invalidates access for any recipient not present in the new epoch — this is the post-compromise security primitive. Forward secrecy of historical documents is **not** provided by design (persistent documents must remain decryptable by current recipients).

```ts
import { addCollectionRecipient, removeRecipient, listRecipients } from "@drakkar.software/starfish-client"

// Grant access (pulls the keyring, appends a wrap entry for the new recipient, pushes back).
await addCollectionRecipient(client, "notes", adderKeys, { subKem: newDeviceKemPub })

// Revoke access (rotates the epoch, re-wraps for the retained set).
await removeRecipient(client, "notes", adderKeys, removedDeviceKemPub)

// List who's in the keyring.
const recipients = await listRecipients(client, "notes")
```

Full API: [docs/ts/client/23-multi-recipient-delegated.md](docs/ts/client/23-multi-recipient-delegated.md).

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
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"
import AsyncStorage from "@react-native-async-storage/async-storage"

// One-time at startup: derive the root identity + self-signed device cap.
const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
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
    // For "delegated" collections, pass a v3 Encryptor:
    encryptor: await createKeyringEncryptor(keyring, deviceKem),
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
    // For "delegated" collections, pass a v3 Encryptor:
    encryptor: await createKeyringEncryptor(keyring, deviceKem),
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

The v3 identity surface — `bootstrapRootIdentity`, `deriveRootIdentity`, `mintDeviceCap`, `mintMemberCap`, `scopes`, the pairing helpers (`buildPairingQr` / `parsePairingQr` / `assemblePairingBundle` / `installPairingBundle` / `buildPairingRequest` / `readPairingRequest` / `buildPairingResponse` / `readPairingResponse` / `deriveCodeKey`), and the keyring/recipient helpers (`createKeyring` / `addRecipient` / `rotateEpoch` / `createKeyringEncryptor` / `addCollectionRecipient` / `removeRecipient` / `listRecipients`) — is on the main entrypoint. See [docs/ts/client/](docs/ts/client/) for guides 11, 23, 24, 25.

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

#### Identity (`bootstrapRootIdentity`)

Passwordless identity derived from a passphrase: Argon2id → HKDF → Ed25519 (sign) + X25519 (KEM) root key pair → self-signed cap-cert.

```ts
import { bootstrapRootIdentity } from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity(passphrase)
// creds = {
//   rootEdPub,                                  // hex 64
//   userId,                                     // hex 32 = sha256(rootEdPub)[0:32]
//   device: { edPriv, edPub, kemPriv, kemPub }, // = root keys on the first device
//   capCert,                                    // self-signed kind:"device", scope: rootAll()
// }

const client = new StarfishClient({
  baseUrl: serverUrl,
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})
```

`userId` is stable across devices (it is a function of `rootEdPub` alone), so URL paths like `/pull/<userId>/notes` keep working everywhere the user pairs in. Additional devices are added with [QR or relay pairing](docs/ts/client/24-pairing.md), never by re-sharing the passphrase — that keeps per-device revocation final.

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
├── examples/
│   ├── ts/ · python/      # Single-file examples, one per v3 feature slice
│   └── app/               # Full-stack chat app (Vite/React + FastAPI) wiring all 6 extensions
├── tests/
│   └── test-vectors/      # Cross-language hash/crypto/protocol test vectors
├── package.json           # pnpm workspace root
└── pnpm-workspace.yaml
```

A runnable end-to-end demo lives in [`examples/app/`](./examples/app/) — a chat
app that exercises identities (with multi-device pairing), keyring, sharing,
entitlements, audit, and queuing together. See its
[README](./examples/app/README.md).

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

**Stress tests** for the append-only feature are kept out of the default run (they push documents to 100k+ elements to characterize parse/serialize cost). Run them opt-in:

```bash
# TypeScript (from packages/ts/server)
STARFISH_STRESS=1 pnpm exec vitest run tests/router/append-only.stress.test.ts --reporter=verbose
# Python (from packages/python/server)
uv run pytest -s -m stress tests/protocol/test_append_stress.py
```

See `docs/ts/server/append-only-collections.md` §Size considerations for what they measure.

The TypeScript client has 259 tests across 23 test files covering sync, crypto, bindings, React hooks, broadcast, retry/circuit breaker, resolvers, migration, validation, polling, history, dedup, export, metrics, Suspense, and more. The TypeScript server has 149 tests across 17 test files covering config, protocol, encryption, router, queue, replica, storage, middleware (CORS, security headers, timeout), ETag, batch pull, field permissions, TTL, OpenAPI, and lifecycle. The Python server has 246 tests.

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

**Accessing request metadata in callbacks — `StoreContext`**

Every store method receives an optional `StoreContext` as its last argument. It carries the collection name, resolved path parameters (e.g. the `identity` value from `/{identity}/collection`), the authenticated caller, their roles, and the operation type. Declare an extra argument in your callback to opt in; old single-argument callbacks are unaffected.

```ts
// TypeScript — opt in by accepting the extra argument
const store = new CustomObjectStore({
  onPut: (key, body, ctx) => {
    console.log(`${ctx?.identity} pushed to ${ctx?.collection}`, ctx?.params)
    return myBackend.set(key, body)
  },
})
```

```python
# Python — arity-sniffed at construction; old lambdas unchanged
async def on_put(key: str, body: str, ctx) -> None:
    print(f"{ctx.identity} pushed to {ctx.collection}", ctx.params)
    await my_backend.set(key, body)

store = CustomObjectStore(on_put=on_put)
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

With `"delegated"` mode the server stores opaque ciphertext (`{_encrypted, _epoch}`) and a plaintext per-collection **keyring document** at `<storagePath>/_keyring` (override with `keyringPath`). The keyring carries one Content Encryption Key (CEK) per epoch, wrapped separately for each recipient via X25519 ECDH + HKDF + AES-256-GCM, signed by the granting device.

Symmetric authority: once a device holds the current CEK, it can encrypt new documents, decrypt every document in every epoch it has a wrap for, wrap the CEK for a new recipient (within its cap-cert's scope), and rotate the epoch to revoke access for anyone not in the new set. What still requires the root Ed25519 key: minting a fresh cap-cert and signing the revocation list.

```json
{
  "name": "vault",
  "storagePath": "users/{identity}/vault",
  "readRoles": ["self", "cap:read:vault"],
  "writeRoles": ["self", "cap:write:vault"],
  "encryption": "delegated",
  "maxBodyBytes": 65536
}
```

```ts
import {
  StarfishClient,
  SyncManager,
  createKeyringEncryptor,
  type Keyring,
} from "@drakkar.software/starfish-client"

const keyring = (await client.pull("/pull/vault/_keyring")).data as Keyring
const encryptor = await createKeyringEncryptor(keyring, {
  kemPubHex: device.kemPub,
  kemPrivHex: device.kemPriv,
})

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/vault`,
  pushPath: `/push/users/${userId}/vault`,
  encryptor,
})

await sync.push({ balance: 1000 })
await sync.pull()  // decrypted plaintext
```

```python
from starfish_sdk import StarfishClient, SyncManager, create_keyring_encryptor

keyring = (await client.pull("/pull/vault/_keyring")).data
encryptor = create_keyring_encryptor(
    keyring,
    {"kem_pub_hex": device["kem_pub"], "kem_priv_hex": device["kem_priv"]},
)

sync = SyncManager(
    client,
    f"/pull/users/{user_id}/vault",
    f"/push/users/{user_id}/vault",
    encryptor=encryptor,
)
await sync.push({"balance": 1000})
await sync.pull()  # decrypted plaintext
```

Full algorithm, recipient lifecycle, and FS stance: [docs/ts/client/23-multi-recipient-delegated.md](docs/ts/client/23-multi-recipient-delegated.md).

### Bundles

Collections with the same `bundle` value share a storage path and expose a combined pull endpoint:

```ts
{ name: "settings", storagePath: "users/{identity}", bundle: "user-data", ... },
{ name: "favorites", storagePath: "users/{identity}", bundle: "user-data", ... },
```

`GET /pull/users/:identity` returns all bundled collections in a single response. Push remains per-collection.

### Queue (change events)

The `@drakkar.software/starfish-queuing` / `starfish-queuing` (Py) extension publishes a lightweight change event after every successful push, via the additive `ServerPlugin.afterWrite` hook. Built-in backends: `MemoryQueue` (testing), `CustomQueue` (callback-based), `NatsQueue` (Python/NATS — `pip install "starfish-queuing[nats]"`).

Queue errors never surface to clients — they are logged and the push response is returned normally. A collection only publishes if it appears in the plugin's `collections` map.

> Full reference: [`docs/ts/queuing/01-overview.md`](docs/ts/queuing/01-overview.md)

#### QueueConfig

| Field | Type | Default | Description |
|---|---|---|---|
| `topic` | `string` | collection name | Topic / NATS subject to publish to |
| `includeParams` | `boolean` | `false` | Include resolved path params in the payload |
| `includeBody` | `boolean?` | `false` | Include push request data in the payload (JSON collections only) |

Each value in the queuing plugin's `collections` map is a `QueueConfig`; collections absent from the map publish nothing.

### List Endpoint

Set `listable: true` on a collection to expose a `GET /list/...` endpoint that returns the existing document keys under the collection's prefix. Clients use this to discover which documents exist — for example, which days have chat messages for a group.

The route drops the last path parameter from `storagePath` and enumerates its values:

| `storagePath` | List route | Returns |
|---|---|---|
| `chats/{groupId}/{day}` | `GET /list/chats/:groupId` | day values |
| `notes/{userId}` | `GET /list/notes` | userId values |

```ts
// TypeScript
{ name: "chat", storagePath: "chats/{groupId}/{day}", readRoles: ["cap:read:chat"], /* ... */, listable: true }
```

```python
# Python
CollectionConfig(name="chat", storage_path="chats/{groupId}/{day}", read_roles=["cap:read:chat"], ..., listable=True)
```

Response: `{ "items": ["2026-04-13", "2026-04-12"], "hasMore": false }`. Pagination: `?limit=N` (default 100, max 1000) and `?after=<item>`.

Set `listValues: true` (`list_values` / alias `listValues` in Python) as well, and the endpoint accepts `?include=values`, returning each document's stored `data` and `hash` alongside its key — `{ "items": [{ "key", "data", "hash" }], "hasMore": false }` — so a client enumerates a directory in one round-trip instead of a list followed by a per-key batch pull. Read auth, pagination, TTL and `fieldPermissions` read-stripping apply exactly as on a regular pull.

> Full reference: [`docs/ts/server/list-endpoint.md`](docs/ts/server/list-endpoint.md)

### Projection (materialized views)

The `@drakkar.software/starfish-projection` / `starfish-projection` (Py) extension maintains a denormalized view of a source collection, via the additive `ServerPlugin.afterWrite` hook. After each successful push to a watched `source` collection it runs an app-supplied pure `project(event)` and applies the result to the store: `{ key, data }` upserts the target document (last-writer-wins by key), `{ key, delete: true }` removes it, `null` ignores the event. The app supplies only the mapping; the plugin owns all store IO.

Writes go in-process (never over HTTP), so the target collection can be declared `pullOnly: true` — clients read/enumerate it, only the projection writes it. Pair it with `listValues` so the whole view is fetchable in one `GET /list/<target>?include=values`. Projection failures are logged and never break the originating client write.

```ts
createProjectionServerPlugin({
  store,
  projections: [{
    source: ["pubspace", "spacediscovery"],
    project: (e) => e.body?.discoverable === true
      ? { key: `spacedir/${e.params.spaceId}`, data: { name: e.body.name } }
      : { key: `spacedir/${e.params.spaceId}`, delete: true },
  }],
})
```

> Full reference: [`docs/ts/projection/01-overview.md`](docs/ts/projection/01-overview.md)

---

### Sharing a collection (member caps)

To grant another user access to a collection, the owner mints a **`member` capability certificate** with `@drakkar.software/starfish-sharing` / `starfish-sharing`. The recipient keeps their own identity; the cap synthesizes a `delegated:<ownerId>:<collection>` role the collection opts into. Authorization flows from the signed cap — the server holds no membership lists.

```ts
// TypeScript — owner mints a writer cap for `bob`
import { mintMemberCap, scopes, addMemberEntry } from "@drakkar.software/starfish-sharing"

const bobCap = await mintMemberCap(
  owner.keys.edPriv, owner.keys.edPub,
  { edPubHex: bob.edPub, kemPubHex: bob.kemPub, userIdHex: bob.userId },
  "shared-team", scopes.writer("shared-team"),
)
await addMemberEntry(client, "shared-team", bobCap, { label: "Bob" }) // owner-only audit roster
// collection: { name: "shared-team", writeRoles: ["delegated:<ownerId>:shared-team"], ... }
```

Bulk membership is one cap per recipient. If you need a server-authoritative allow-list (the old `createGroupRoleEnricher` behavior, **removed in 3.0**), write your own `RoleEnricher` (a few lines) that reads your list and grants a role, then compose it with `composeEnrichers`. Request-to-join is an app-level recipe (a `_requests` collection + owner-side `mintMemberCap`), not a built-in.

**Public links.** For a plaintext (`encryption: "none"`) share by **link** rather than per-recipient cap, use `createPublicLink` / `parsePublicLink` / `redeemPublicLink`. It packs an `audience` cap-cert into a URL `#fragment` with an optional, server-enforced identity allow-list (`allowedIdentities`; omit for "anyone") and optional expiry. Redeemers sign with their own key (sent as `X-Starfish-Pub`), so the link embeds no private key and writes stay attributable. See [`docs/ts/sharing/02-public-links.md`](docs/ts/sharing/02-public-links.md).

> Full reference: [`docs/ts/server/group-access.md`](docs/ts/server/group-access.md) · [`docs/ts/sharing/`](docs/ts/sharing/)

---

### Entitlement-Based Access Control

Use `createEntitlementRoleEnricher` / `create_entitlement_role_enricher` to gate collections behind per-user feature slugs. The enricher reads a per-user entitlement document from the ObjectStore and grants roles of the form `"entitlement:<slug>"`. Collections declare which slugs unlock access in `readRoles`/`writeRoles`.

```ts
// TypeScript
import { composeEnrichers } from "@drakkar.software/starfish-server"
import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"

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
from starfish_server import compose_enrichers
from starfish_entitlements import create_entitlement_role_enricher, EntitlementRoleEnricherOptions

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

#### Append-only collections

Set `appendOnly: { type: "by_timestamp" }` on a collection to append every push to a stored array (default field: `items`) as a `{ ts, data }` element. There is no hash/conflict check — an authorized append is always accepted, never 409 (a client may supply a strictly-increasing `ts`, else the server assigns one). Pull with `?checkpoint=<ts>` to get only elements appended after a timestamp. Works under both `encryption: "none"` and `"delegated"` (the client encrypts each element's `data`; the server stores it opaquely). By default each document holds the whole array, so append is O(N) per call (building a log is O(N²)) and a checkpoint pull still parses the full document. Opt into `chunkSize` (segmented storage — bounded-cost append; checkpoint/last pulls read only the chunks they need) and/or `maxItems` (cap appends, returning `409 append_limit_exceeded`), or partition by a path param (see the append-only docs §Bounding & scaling).

**Author proof (default on).** Every append carries a cryptographic author signature: `client.append()` signs the element `data` with the same key that authenticates the request, and the server requires `authorPubkey` to be that verified presenter and the signature to verify (`signAppendAuthor` / `verifyAppendAuthor`). The proof is stored on each element, so a reader verifies *who* wrote it instead of trusting a self-declared id. Set `appendOnly: { type: "by_timestamp", requireAuthorSignature: false }` to opt out for an unauthenticated/public-write log. See the append-only docs §Author proof.

```ts
// TypeScript — stored array of { ts, data }
{ name: "events", storagePath: "events", /* ... */, appendOnly: { type: "by_timestamp" } }
```

```python
# Python — stored array of { ts, data }
CollectionConfig(name="events", storage_path="events", ..., append_only=AppendOnlyConfig(type="by_timestamp"))
```

Use `appendOnly: { type: "by_timestamp", persist: false }` (`AppendOnlyConfig(type="by_timestamp", persist=False)` in Python) to skip storage entirely — pushes are accepted and emit a change event (consumed by the `starfish-queuing` plugin), but nothing is stored (replaces the old `queueOnly` flag):

```ts
// server config — persist:false is a server flag
{ name: "events", storagePath: "events/{eventId}", /* ... */, appendOnly: { type: "by_timestamp", persist: false } }
// queuing plugin — wire the topic for "events"
createQueuingServerPlugin({ queue, collections: { events: { topic: "analytics.events", includeParams: false } } })
```

Client usage:

```ts
// Append an item (baseHash=null means "no conflict check")
await client.push("/push/events", { type: "click" }, null)

// Full pull → returns T[]
const items = await client.pull("/pull/events", { appendField: "items" })

// Incremental pull — only items appended since last sync (O(M) payload, not O(N))
const newItems = await client.pull("/pull/events", { appendField: "items", since: lastSyncTimestamp })

// Custom field name + last K items
const logs = await client.pull("/pull/audit", { appendField: "logs", last: 50 })
```

```python
# Append an item
await client.push("/push/events", {"type": "click"}, None)

# Incremental pull
new_items = await client.pull("/pull/events", since=last_sync_timestamp)

# Last 50 items, custom field
logs = await client.pull("/pull/audit", append_field="logs", last=50)
```

Push CPU is O(1) — the stored hash covers only the last item and array length, not the full array.

> Full reference: [`docs/ts/server/append-only-collections.md`](docs/ts/server/append-only-collections.md)

#### Root-only collections

Set `rootOnly: true` (`root_only=True` in Python) to restrict a collection to the user's **root device**: every paired/provisioned device cap and member cap gets a 403 — on standalone pull/list/push and on bundle pulls. The root device is detected by `isRootDeviceCap` (a self-signed `kind:"device"` cap, `iss === sub`), surfaced as the synthesized `device:root` role. Config load rejects `rootOnly` combined with a `public` read/write role.

```ts
// TypeScript
{ name: "settings", storagePath: "users/{identity}/settings", /* ... */, rootOnly: true }
```

```python
# Python
CollectionConfig(name="settings", storage_path="users/{identity}/settings", ..., root_only=True)
```

> Full reference: [`docs/ts/server/root-only-collections.md`](docs/ts/server/root-only-collections.md)

#### Plugin config (per-collection)

The queuing plugin owns the per-collection config — it is no longer set on `CollectionConfig`:

```ts
// TypeScript
createQueuingServerPlugin({
  queue,
  collections: {
    posts: { includeParams: false },  // topic = "posts" (collection name)
    // comments: { topic: "data.comments.changed", includeParams: true, includeBody: true },
  },
})
```

```python
# Python
create_queuing_server_plugin(
    queue=queue,
    collections={
        "posts": QueueConfig(include_params=False),
        # "comments": QueueConfig(topic="data.comments.changed", include_params=True, include_body=True),
    },
)
```

#### Server setup

```ts
// TypeScript — CustomQueue (any backend via callback)
import { createQueuingServerPlugin, CustomQueue } from "@drakkar.software/starfish-queuing"

const queue = new CustomQueue({
  onPublish: async (subject, payload) => {
    await natsClient.publish(subject, payload)
  },
})

const queuing = createQueuingServerPlugin({ queue, collections: { posts: { includeParams: false } } })
const sync = createSyncRouter({ store, config, roleResolver, plugins: [queuing] })
// queuing.shutdown closes the queue when passed to createGracefulShutdown({ plugins: [queuing] })
```

```python
# Python — NatsQueue
from starfish_queuing import create_queuing_server_plugin, QueueConfig
from starfish_queuing.nats import NatsQueue, NatsQueueOptions

queue = NatsQueue(NatsQueueOptions(servers="nats://localhost:4222"))
queuing = create_queuing_server_plugin(queue=queue, collections={"posts": QueueConfig()})

sync_router = create_sync_router(SyncRouterOptions(
    store=store, config=config, role_resolver=role_resolver, plugins=[queuing],
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
import type { QueueMessage } from "@drakkar.software/starfish-queuing"
```

```python
from starfish_queuing import QueueMessage
```

### Config endpoint

`GET /config` lets clients discover server capabilities at runtime — collection names, size limits, encryption modes, and supported MIME types.

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

There is no per-collection `publicKey` config field — v3 `"delegated"` encryption distributes recipient keys via the per-collection `_keyring` document, not through `/config` (see [`docs/ts/client/23-multi-recipient-delegated.md`](docs/ts/client/23-multi-recipient-delegated.md)).

Fetch from the client:

```ts
import { fetchServerConfig } from "@drakkar.software/starfish-client"
const config = await fetchServerConfig("https://api.example.com/v1")
// config.collections[0].maxBodyBytes, .encryption, .appendOnly, …
```

```python
from starfish_sdk import fetch_server_config
config = await fetch_server_config("https://api.example.com/v1")
# config.collections[0].max_body_bytes, .encryption, .append_only, …
```

> Full reference: [`docs/ts/server/config-endpoint.md`](docs/ts/server/config-endpoint.md)

### Replicas

The replica system lets you run multiple Starfish servers that stay in sync. A **primary** server holds the source of truth; **replicas** pull from it and serve reads locally. Replication ships as a server plugin — [`@drakkar.software/starfish-replica`](packages/ts/replica) / [`starfish-replica`](packages/python/replica) — that owns its config and hooks into the pull/push routes. Install it and pass it via `plugins`.

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
| `scheduled` | Every `intervalMs` in the background |
| `on_pull` | Before each client `GET /pull/…` (respects `onPullMinIntervalMs` cooldown) |

#### Replica server

```ts
// TypeScript
import { createSyncRouter, createGracefulShutdown } from "@drakkar.software/starfish-server"
import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"

const replica = createReplicaServerPlugin({
  store,
  syncConfig: config,
  collections: {
    posts: {
      url: "https://primary.example.com/v1",
      pullPath: "/pull/posts/featured",
      intervalMs: 30_000,
      headers: { Authorization: "Bearer replica-token" },
      writeMode: "pull_only",
      syncTriggers: ["scheduled"],
    },
  },
})

const sync = createSyncRouter({ store, config, roleResolver, plugins: [replica] })

replica.manager.start()                      // Node.js: start background sync
createGracefulShutdown({ plugins: [replica] }) // shutdown hook stops the timers
// CF Workers: use replica.manager.syncNow()/syncAll() from Cron Triggers instead
```

```python
# Python
from starfish_server import create_sync_router, SyncRouterOptions
from starfish_replica import create_replica_server_plugin, RemoteConfig

replica = create_replica_server_plugin(
    store=store, sync_config=config,
    collections={
        "posts": RemoteConfig(
            url="https://primary.example.com/v1",
            pullPath="/pull/posts/featured",
            interval_ms=30_000,
            write_mode="pull_only",
            sync_triggers=["scheduled"],
            headers={"Authorization": "Bearer replica-token"},
        ),
    },
)

sync_router = create_sync_router(SyncRouterOptions(
    store=store, config=config, role_resolver=role_resolver, plugins=[replica.plugin],
))

@asynccontextmanager
async def lifespan(app):
    await replica.manager.start()
    yield
    await replica.manager.stop()
```

> Full reference: [`docs/ts/replica/01-overview.md`](docs/ts/replica/01-overview.md)

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
