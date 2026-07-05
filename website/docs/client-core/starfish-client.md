---
sidebar_position: 1
---

# StarfishClient

Low-level HTTP client for the Starfish sync protocol. Handles cap-cert
authentication, per-request Ed25519 signing, request formatting, and
response parsing.

> **Prerequisites:** [Getting Started](/getting-started/intro)

## Constructor

```ts
import {
  StarfishClient,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})
```

### `StarfishClientOptions`

```ts
interface StarfishClientOptions {
  /** Base URL of the Starfish server (e.g. "https://api.example.com/v1") */
  baseUrl: string
  /**
   * Cap-cert provider. When set, the client signs every outgoing request:
   * each call carries `Authorization: Cap <base64(stableStringify(cap))>`
   * plus `X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce` headers.
   * Omit for unauthenticated public-read collections.
   */
  capProvider?: StarfishCapProvider
  /** Custom fetch implementation (defaults to global fetch) */
  fetch?: typeof fetch
  /**
   * Optional offline-first read-through ciphertext cache.
   * See [Offline & Connectivity](/state-offline/offline-connectivity).
   *
   * **Note:** persist-backed Zustand stores (`createStarfishStore` with a `storage`)
   * are already offline-first for reads — a transport failure during `pull()` preserves
   * the persisted data and sets `stale: true` without surfacing an error. You only need
   * a client `cache` when you want ciphertext-at-rest storage between restarts or
   * stale-while-revalidate on specific HTTP status codes (`cacheFallbackStatuses`).
   */
  cache?: PullCache
  /** Optional TTL for cache entries in ms. Omit for entries that never expire. */
  cacheMaxAgeMs?: number
  /**
   * HTTP statuses that fall back to the cached snapshot instead of throwing
   * (stale-while-revalidate). Recommended: `[429, 500, 502, 503, 504]`.
   * See [Error Classification & Retry](/client-core/error-retry#stale-while-revalidate).
   */
  cacheFallbackStatuses?: number[]
  /**
   * Called after a background revalidation succeeds following a
   * `cacheFallbackStatuses` hit. Use to signal reachability to the host app.
   */
  onRevalidated?: (path: string, result: PullResult) => void
}
```

The v2 `auth: AuthProvider` option (Bearer-token headers) was removed in
3.0. All authenticated requests now use the `capProvider` shape below;
there is no `Authorization: Bearer` path. See
[the migration guide](/migration/v2-to-v3) if you're coming from
2.x.

## Cap Provider

`capProvider.getCap()` returns the device's cap-cert and its Ed25519
private key. The client uses the cap-cert as the `Authorization: Cap …`
header value, and signs every request with the private key (request hash
+ ts + nonce → `X-Starfish-Sig` etc.).

```ts
interface StarfishCapProvider {
  getCap(): Promise<{ cap: CapCert; devEdPrivHex: string }>
}
```

Implementations are expected to cache; the client may call `getCap()` once
per authenticated request, so a typical implementation reads `creds` from
local storage and returns the already-derived cap.

```ts
const capProvider: StarfishCapProvider = {
  getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
}
```

For a deeper look at the cap-cert shape, scopes, and TTLs see
[25. Capability Certs](/encryption-identity/capability-certs). For request-signing
details see [03. SyncManager](/client-core/sync-manager) and
`packages/ts/protocol/src/request-signing.ts`.

## Methods

### `pull(path, checkpoint?)`

Fetches synced data from the server. A regular collection always returns the **full document** — incremental `?checkpoint=` sync is now an append-only-only feature (use `pull(path, { appendField, since })` for append logs). The `checkpoint` number is still accepted for wire-compatibility but is ignored by regular collections.

```ts
const result = await client.pull(`/pull/users/${userId}/settings`)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `string` | Server endpoint path |
| `checkpoint` | `number` | Optional, accepted for back-compat. Ignored by regular collections (they always return the full document). |

**Returns:** `Promise<PullResult>`

```ts
interface PullResult {
  data: Record<string, unknown>
  hash: string
  timestamp: number
  authorPubkey?: string
  authorSignature?: string
}
```

**Wire format:**

```
GET {baseUrl}{path}?checkpoint={timestamp}
Authorization: Cap {base64(stableStringify(capCert))}
X-Starfish-Sig:   {base64(ed25519 sig)}
X-Starfish-Ts:    {unix-ms}
X-Starfish-Nonce: {base64(16 random bytes)}
Accept: application/json

Response 200:
{
  "data": { ... },
  "hash": "sha256-hex",
  "timestamp": 1712345678
}
```

### `push(path, data, baseHash, authorSignature?)`

Pushes data to the server. Uses optimistic concurrency — the server rejects the push if `baseHash` doesn't match the current server hash.

```ts
const success = await client.push(
  `/push/users/${userId}/settings`,
  { theme: "dark", lang: "en" },
  lastKnownHash,  // null for first push
)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `string` | Server endpoint path |
| `data` | `Record<string, unknown>` | The document to push |
| `baseHash` | `string \| null` | Hash of the last known server version. `null` for first push |
| `authorSignature` | `string` | Optional. Signature for data provenance |

**Returns:** `Promise<PushSuccess>`

```ts
interface PushSuccess {
  hash: string
  timestamp: number
}
```

**Wire format:**

```
POST {baseUrl}{path}
Authorization: Cap {base64(stableStringify(capCert))}
X-Starfish-Sig:   {base64(ed25519 sig)}
X-Starfish-Ts:    {unix-ms}
X-Starfish-Nonce: {base64(16 random bytes)}
Content-Type: application/json

{
  "data": { ... },
  "baseHash": "sha256-hex-or-null"
}

Response 200: { "hash": "sha256-hex", "timestamp": 1712345678 }
Response 409: Conflict (baseHash mismatch)
```

## Error Handling

### `ConflictError`

Thrown when `push()` receives a 409 response (hash mismatch). This means another client pushed a change since your last pull.

```ts
import { ConflictError } from "@drakkar.software/starfish-client"

try {
  await client.push(path, data, staleHash)
} catch (err) {
  if (err instanceof ConflictError) {
    // Pull latest, merge, retry
  }
}
```

### `StarfishHttpError`

Thrown for any non-OK HTTP response other than 409.

```ts
import { StarfishHttpError } from "@drakkar.software/starfish-client"

try {
  await client.pull(path)
} catch (err) {
  if (err instanceof StarfishHttpError) {
    console.log(err.status) // e.g. 403
    console.log(err.body)   // server error message
  }
}
```

## Custom Fetch

Pass a custom `fetch` implementation for environments without a global `fetch`, or for adding interceptors:

```ts
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider,
  fetch: myCustomFetch,
})
```

## Sealed Blobs

`sealAndPushBlob` / `pullAndOpenBlob` are the one-shot seal/transport helpers over `pushBlob`/`pullBlob` (see [E2EE Parquet](/analytics/parquet-duckdb#e2ee-parquet-createsealed) for a full example). For a caching layer, **`createSealedBlobStore`** wraps that core with an in-memory decrypted-plaintext cache (default 64 MB, evicted in insertion order) and a KV-persisted post-seal ciphertext cache (default 4 MB), so blobs reopen offline / after reload without a round-trip:

```ts
import { createSealedBlobStore, type SealedBlobPaths } from "@drakkar.software/starfish-client"

interface Ctx {
  spaceId: string
}

const paths: SealedBlobPaths<Ctx> = {
  pushPath: (id, ctx) => `/push/spaces/${ctx.spaceId}/objects/blob/${id}`,
  pullPath: (id, ctx) => `/pull/spaces/${ctx.spaceId}/objects/blob/${id}`,
  aad: (id, ctx) => `spaces/${ctx.spaceId}/objects/blob/${id}`,
}

const store = createSealedBlobStore({
  paths,
  maxBytes: 10 * 1024 * 1024, // 10 MiB
  kvAdapter: myAsyncStorage, // optional; omit to disable persistence
})

// Seal (sealer non-null) or store plaintext (sealer: null) and mint an id
const id = await store.upload(client, sealer, bytes, { spaceId })

// Fetch + unseal: memory cache → persisted cache → network
const plaintext = await store.load(client, sealer, id, { spaceId })
```

The app supplies only the path/AAD strategy; the store owns id generation, size-guarding (throws `FileTooLargeError` when `bytes` exceeds `maxBytes`), sealing, transport, and eviction.

## Next Steps

- [SyncManager](/client-core/sync-manager) — wraps `StarfishClient` with encryption, conflict retry, and state tracking
- [Encryption](/encryption-identity/encryption) — E2E encryption details
- [25. Capability Certs](/encryption-identity/capability-certs) — cap-cert shape, scopes, TTLs
- [Error Classification & Retry](/client-core/error-retry) — retry wrapper and circuit breaker via custom `fetch`
- [Logging & Observability](/integration-operations/logging-observability) — request logging via custom `fetch`
