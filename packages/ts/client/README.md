# @drakkar.software/starfish-client

TypeScript client SDK for [Starfish](../../../README.md) — browser, Node.js, and React Native. Pull/push documents with hash-based conflict detection, end-to-end multi-recipient encryption, and cap-cert authorization.

## Install

```bash
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-protocol
```

Optional state bindings: `npm install zustand` (or `@legendapp/state`).

## What's in v3.0

Starfish 3.0 is a clean break from 2.x. The v2 `deriveCredentials` / `generatePassphrase` / Bearer-token `authProvider` / `signData` / `signatureVerifier` / `createEncryptor` / `group-crypto` surface is **deleted**. See [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).

The v3 model in one sentence: a passphrase derives an Ed25519+X25519 **root identity**, which signs **capability certificates** for each device or member, and each authenticated request is itself Ed25519-signed under the cap's subject key.

## Quickstart (v3)

```ts
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
  createKeyringEncryptor,
  type Keyring,
} from "@drakkar.software/starfish-client"

// 1. Derive root identity + self-signed cap-cert from a passphrase.
const creds = await bootstrapRootIdentity(passphrase)
// creds = { rootEdPub, userId, device: {edPriv,edPub,kemPriv,kemPub}, capCert }

// 2. Wire StarfishClient to a CapProvider — every request is signed.
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// 3. (Delegated only) build an encryptor from the collection's keyring.
const keyring = (await client.pull(`/pull/notes/_keyring`)).data as Keyring
const encryptor = await createKeyringEncryptor(
  keyring,
  { kemPubHex: creds.device.kemPub, kemPrivHex: creds.device.kemPriv },
  { trustedAdders: [creds.rootEdPub] },   // required — pubkey(s) you trust to grant access
)

// 4. Sync with optional per-push author signature.
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

await sync.push({ items: ["note 1"] })  // sealed, signed, hash-checked
await sync.pull()                        // decrypted plaintext
```

## Identity & key derivation

```ts
import { bootstrapRootIdentity, deriveRootIdentity } from "@drakkar.software/starfish-client"
```

- `deriveRootIdentity(passphrase)` — passphrase → `{ userId, keys: {edPriv, edPub, kemPriv, kemPub} }`. Pure derivation, no cap-cert.
- `bootstrapRootIdentity(passphrase)` — same derivation plus a self-signed `kind: "device"` full-scope cap-cert. Use this on the first device.

`userId = sha256(rootEdPub)[0:32]`. Two independent HKDF derivations (signing vs KEM) give full domain separation.

Details: [docs/ts/client/11-identity-key-derivation.md](../../../docs/ts/client/11-identity-key-derivation.md).

## Cap-cert minting

```ts
import { mintDeviceCap, mintMemberCap, scopes } from "@drakkar.software/starfish-client"
```

- `mintDeviceCap(rootEdPriv, rootEdPub, subject, scope, opts?)` — subject acts as a proxy for the issuer (`auth.identity = issUserId`). Used for additional devices the user controls.
- `mintMemberCap(rootEdPriv, rootEdPub, subject, scope, opts?)` — subject keeps its own identity (`auth.identity = subUserId`); cap adds collection-scoped roles only.

### Scope presets

| Preset | Ops | Paths |
|---|---|---|
| `scopes.readOnly(c)` | `read`, `list` | `c/*` |
| `scopes.writer(c)` | `read`, `list`, `write` | `c/*`, `!c/_keyring` (cannot grant new recipients) |
| `scopes.admin(c)` | `read`, `list`, `write` | `c/*` (can grant via the keyring) |
| `scopes.rootAll()` | all | `*` (device caps only) |

The `!` prefix in `paths` is a denylist; explicit deny beats wildcard allow.

Details: [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md).

## Pairing additional devices

Three onboarding flows, all returning the same `DeviceCredentials` shape:

| Flow | Network | Helper |
|---|---|---|
| Bootstrap (first device) | none | `bootstrapRootIdentity(passphrase)` |
| QR (in-person, server-free) | none | `buildPairingQr` → `parsePairingQr` → `assemblePairingBundle` → `installPairingBundle` |
| Server-relay (remote, 6-digit code) | 2 TTL'd Starfish documents | `buildPairingRequest` → `readPairingRequest` → `buildPairingResponse` → `readPairingResponse` → `installPairingBundle` |

```ts
import {
  bootstrapRootIdentity,
  buildPairingQr,
  parsePairingQr,
  assemblePairingBundle,
  installPairingBundle,
  buildPairingRequest,
  readPairingRequest,
  buildPairingResponse,
  readPairingResponse,
  deriveCodeKey,
} from "@drakkar.software/starfish-client"
```

`deriveCodeKey(code, salt, iterations?)` is the PBKDF2-HMAC-SHA256 (200 000 iterations by default) used by the relay flow.

**Root pinning is mandatory.** `installPairingBundle(bundle, device, opts)` throws unless `opts` supplies either `expectedRootEdPub` (pin the account's known root pubkey) or `confirmUnpinnedRoot: (rootEdPub) => boolean` (a first-contact callback that surfaces the bundle's root for explicit user confirmation). Passing neither used to silently trust *any* root — a confused-deputy vulnerability that let an attacker provision the device into their own account. For one-way provisioning over an already-trusted channel use `installProvisionedDevice`, which auto-acknowledges first-contact.

Full walkthroughs: [docs/ts/client/24-pairing.md](../../../docs/ts/client/24-pairing.md).

## Multi-recipient delegated encryption

A `"delegated"` collection has data documents (opaque ciphertext) plus one **keyring document** at `<collection>/_keyring` that wraps the current Content Encryption Key (CEK) for each recipient via X25519 ECDH + HKDF + AES-256-GCM (HPKE-DHKEM style).

### Low-level keyring API

```ts
import {
  createKeyring,
  addRecipient,            // low-level: append entry to an in-memory keyring
  rotateEpoch,
  wrapForRecipient,
  unwrapFromEntry,
  verifyEntrySignature,
  createKeyringEncryptor,
  type Keyring,
  type KeyringEpoch,
  type WrappedKeyEntry,
  type KeyringEncryptor,
  KEYRING_WRAP_SALT,
  KEYRING_WRAP_INFO,
  KEYRING_IV_BYTES,
} from "@drakkar.software/starfish-client"
```

- `createKeyring(adder, recipients, cek?, addedAt?)` — first-time setup, generates a CEK if not provided.
- `addRecipient(keyring, adder, currentCek, recipientKemHex, addedAt?)` — appends one wrap entry to the current epoch.
- `rotateEpoch(keyring, adder, retainedRecipients, addedAt?)` — mints a fresh CEK in `currentEpoch + 1`, re-wraps for the retained set.
- `createKeyringEncryptor(keyring, deviceKem, { trustedAdders, minEpoch? })` — returns an `Encryptor` compatible with `SyncManager`. Encrypts under `currentEpoch`; decrypts any epoch the device has a wrap for. `trustedAdders` is **required** (throws without it); optional `minEpoch` rejects a rolled-back keyring below the last-seen epoch.

### Collection-scoped recipient management

```ts
import {
  addCollectionRecipient,   // adds + pushes the keyring back to the server
  removeRecipient,
  listRecipients,
  currentEpoch,
  keyringPathFor,
  type RecipientRef,
  type AdderKeys,
  type ListedRecipient,
} from "@drakkar.software/starfish-client"
```

These wrap the low-level helpers with HTTP I/O via `StarfishClient`: each operation pulls the keyring, mutates it, and pushes back with hash-checked optimistic concurrency. `addCollectionRecipient`, `removeRecipient`, and `listRecipients` all **require** a `trustedAdders` pin (they throw without one); `listRecipients` returns only provenance-verified entries.

Details + algorithm + threat model: [docs/ts/client/23-multi-recipient-delegated.md](../../../docs/ts/client/23-multi-recipient-delegated.md).

## `StarfishClient`

```ts
new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider,            // v3 — signs every request. Replaces v2 `auth`/`authProvider`.
  fetch,                  // optional custom fetch
  cache,                  // optional offline-first read-through cache — see below
  cacheMaxAgeMs,          // optional TTL (ms) for cache entries
  cacheFallbackStatuses,  // optional — serve cache on 429/5xx (stale-while-revalidate)
  onRevalidated,          // optional — called after a background revalidation succeeds
})
```

`StarfishCapProvider` is a single-method protocol: `getCap(): Promise<{ cap: CapCert, devEdPrivHex: string }>`. Implementations are expected to cache. When a `capProvider` is set, every outgoing request carries `Authorization: Cap <base64(stableStringify(cap))>` plus `X-Starfish-Sig`, `X-Starfish-Ts`, `X-Starfish-Nonce`.

Omit `capProvider` for unauthenticated public reads.

### Offline-first read cache

**Persist-backed Zustand stores are offline-first for reads without a client `cache`.** When
`createStarfishStore` is used with a `storage`, the persisted `starfish-{name}` entry rehydrates
`data` on cold start. If the first `pull()` then fails because the transport is unreachable (offline /
DNS / timeout), `pull()` preserves the already-shown data and sets `stale: true` — no error, no empty
screen. HTTP errors (4xx/5xx), aborts, and decrypt failures still set `error` as usual.

The client `cache` (`PullCache`) remains available for additional capabilities:

Pass a `cache` (a `PullCache`: `{ get(k): Promise<string|null>; set(k, v): Promise<void> }`, host-backed by `localStorage`/`AsyncStorage`/etc.) to the client for:

- **Write-through:** a successful pull stores the raw `{data, hash, timestamp}` keyed by document path.
- **Offline fallback (without a persist-backed store):** a pull that fails because the **transport** is unreachable returns the last cached snapshot, tagged so callers can tell it's stale (`pullWasFromCache(result)`).
- **Real HTTP errors propagate:** 404/403 are genuine server answers — the cache is *not* consulted, so "no document yet" and "access denied" keep their meaning. 429 and 5xx can optionally be caught via `cacheFallbackStatuses` (see below).
- **Error-triggered stale-while-revalidate:** set `cacheFallbackStatuses: [429, 500, 502, 503, 504]` to make transient server failures serve the last-synced snapshot immediately and retry in the background (honoring `Retry-After`). When the live response arrives, the cache is updated and `onRevalidated` fires. No snapshot → the error propagates as usual. Do NOT include 403/404 — they are genuine answers, not transient failures.
- **Proactive stale-while-revalidate (`staleWhileRevalidate` pull option):** pass `{ staleWhileRevalidate: true }` to `client.pull(path, { staleWhileRevalidate: true })` to serve the cached snapshot immediately and revalidate in the background on every read (not just on errors). On a cache hit the cached result is returned at once (tagged via `pullWasFromCache`) and the background fetch fires immediately (no initial delay). On a miss it falls through to a normal network-first pull. `onRevalidated` fires on success with the fresh `PullResult`. Both SWR paths share the same dedup loop — a concurrent error-triggered loop and an SWR-on-read loop for the same document collapse to one.
- **`cacheMaxAgeMs`:** an entry older than this is treated as a miss (both cache-first paint and offline fallback); omit for entries that never expire (recommended for offline-first, where any last-synced data beats none).
- **Ciphertext-at-rest by construction:** the cache stores the raw server payload, which for E2E (`delegated`) collections is the sealed ciphertext the server holds — never the decrypted form. Decryption happens in memory on read (see `SyncManager.seedFromCache`).
- **`client.peekCache(path)`** reads the cached snapshot *without* a network round-trip — the basis for cache-first paint.

Append collections are not cached here; they own warm-start persistence via `AppendLogCursor` (`persistEncrypted`).

## `SyncManager`

```ts
new SyncManager({
  client, pullPath, pushPath,
  encryptor,              // typically createKeyringEncryptor(...)
  signer,                 // SyncSigner — replaces v2 `signData`
  onConflict, maxRetries, validate, logger,
})
```

- `signer.getSigner()` returns `{ devEdPubHex, sign(payload) }`. When set, every push attaches `authorPubkey = cap.sub` and `authorSignature = base64(Ed25519(payload))` over the encrypted payload (without the author fields).
- `encryptor` is the only encryption option — the v2 single-secret `encryptionSecret`/`encryptionSalt` shorthand was removed in v3.
- `onConflict` resolves write conflicts on push *and* reconciles a pull against un-pushed local writes. On a zustand-bound store, a `pull()` while the store is `dirty` merges the fetched snapshot with the local data through this resolver (rather than overwriting it), so an optimistic write isn't lost when a pull races a `set()`. Use a union/CRDT-style resolver (`createUnionMerge`) for append-style collections so both the local and remote writes survive; `SyncManager.resolve(local, remote)` exposes the same merge for callers that need it.
- **Offline-first:** Zustand stores backed by `storage` are offline-first without any client `cache` — a transport failure during `pull()` preserves the persisted data and sets `stale: true` on the store. When a client `cache` is also configured, `seedFromCache()` additionally populates `localData` from the ciphertext cache without a network round-trip (decrypting in memory for E2E collections); `getLastPullFromCache()` reports whether the latest `pull()`/seed came from that cache. On a zustand store, the `stale` flag tracks both sources: it is set by an offline `pull()` (no cache needed) and by `seed()` (cache-first paint before the initial live pull).
- **`SyncManager.ingest(result: PullResult)`** applies an externally-delivered `PullResult` to the manager's state (decrypting for E2E, updating `localData`/`lastHash`/`lastCheckpoint`, clearing `lastFromCache`) without a network call. Used by the zustand binding's `mergeResult` action to absorb background revalidation results.

**Auto-merge on revalidation:** when `cacheFallbackStatuses` or `staleWhileRevalidate` triggers a background revalidation, `useSyncInit` and `acquireSyncStore` automatically push the fresh `PullResult` into the bound store via `mergeResult` — the store repaints without waiting for the next explicit `pull()`. The consumer's own `onRevalidated` callback is still called after the store update. The `mergeResult` store action is also available for manual use when a caller holds a fresh `PullResult` it wants to push into the store without an extra round-trip.

## `AppendLogCursor`

Incremental, stateful cursor over an append-only collection — the log counterpart to `SyncManager`. It owns the accumulated array and pulls only what's new; the checkpoint is **derived from the last element it holds**, so it resumes from persisted data on a fresh page.

```ts
const log = new AppendLogCursor({
  client, pullPath: "/pull/events",
  appendField,            // default "items"
  initialItems,           // warm-start seed (raw {ts,data} envelopes) — or pass `since`
  encryptor,              // optional: decrypt each element's data (ts/author preserved)
  verifyAuthor,           // optional: true | { expectedAuthorPubkey?, alg? }
  onElementError,         // optional: "throw" (default) | "skip" — see below
  persistEncrypted,       // optional: keep ciphertext for E2EE-safe persistence — see below
})
const fresh = await log.pull()  // only elements newer than the last held (safe to call concurrently)
log.getItems()                  // full accumulated log (ciphertext under persistEncrypted)
await log.getDecryptedItems()   // full log decrypted — render warm-started history
log.getCheckpoint()             // max ts held — persist, and restore via setCheckpoint()
```

- Cold start (no seed) → first `pull()` fetches the whole collection; warm start (seeded) → resumes incrementally.
- `verifyAuthor` verifies each element's author signature over the stored (pre-decryption) data and throws `AppendAuthorError` atomically on any failure (nothing is appended, checkpoint unchanged).
- `onElementError: "skip"` drops an element that fails verify/decrypt **and advances the checkpoint past it** (never re-fetched), so one unreadable element in a multi-writer / E2EE log can't blank the whole log. Default `"throw"` keeps the atomic behavior. SECURITY: `"skip"` also drops author-verification failures silently — combine with `verifyAuthor.expectedAuthorPubkey` or a post-pull `authorPubkey` check for strict authorship.
- `persistEncrypted: true` (with an `encryptor`) stores each element's **ciphertext** so `getItems()` is safe to persist at rest for an E2EE log; `pull()` still returns decrypted, and `getDecryptedItems()` decrypts the full held log for warm-start rendering.
- `pull()` is safe to call concurrently — overlapping calls serialize internally so they never double-append a window.
- **Reactive bindings:** `createStarfishLog` (Zustand, `./zustand`) + hooks `useStarfishLog` / `useStarfishLogItems` / `useLogStatus` / `useLogConnectivity`; `createStarfishLogObservable` (Legend, `./legend`); `createAppendLogMobileLifecycle` (pull on app foreground). `startPolling` and `createSuspenseResource` work with `cursor.pull()` directly.

## Other utilities

The package also re-exports the v2 ergonomics that survived intact: `consoleSyncLogger`, `noopSyncLogger`, `createMetricsCollector`, `createMigrator`, `createSchemaValidator`, `classifyError`, conflict resolvers (`createUnionMerge`, `createSoftDeleteResolver`, `timestampWinner`, `pruneTombstones`), `SnapshotHistory`, `startPolling`/`startAdaptivePolling`, `createDedupFetch`, `fetchServerConfig`, `pullEntitlements`, `createIndexedDBStorage`, `exportData`/`importData`, `createDebouncedSync`/`createDebouncedPush`, `createMultiStoreSync`, `createMobileLifecycle`, and the Zustand/Legend bindings via the `./zustand` and `./legend` subpaths.

See the root [README.md](../../../README.md) for the catalog and [docs/ts/client/](../../../docs/ts/client/) for in-depth guides.

## Removed in v3.0

`deriveCredentials`, `generatePassphrase`, `buildInviteUrl`, `parseInviteUrl` (the v2 passphrase identity surface), `createEncryptor` and the `SyncManager` `encryptionSecret`/`encryptionSalt`/`encryptionInfo` options, `wrapGroupKey`, `createGroupKeyring`, `addGroupMember`, `rotateGroupKey`, `createGroupEncryptor`, the v2 `auth`/`authProvider` Bearer hook, the `signData` callback, and the `signatureVerifier` server hook are all gone. Code that imports any of them will fail to build against v3.

Migration runbook: [docs/migration/v2-to-v3.md](../../../docs/migration/v2-to-v3.md).
