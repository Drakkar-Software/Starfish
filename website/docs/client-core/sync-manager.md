---
sidebar_position: 2
---

# SyncManager

High-level sync orchestrator that wraps `StarfishClient` with automatic encryption, conflict resolution, retry logic, and state tracking.

> **Prerequisites:** [Getting Started](/getting-started/intro), [StarfishClient](/client-core/starfish-client)

## Constructor

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

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${creds.userId}/settings`,
  pushPath: `/push/users/${creds.userId}/settings`,
})
```

### `SyncManagerOptions`

```ts
interface SyncManagerOptions {
  client: StarfishClient
  pullPath: string
  pushPath: string

  /** Custom conflict resolver. Defaults to remote-wins deep merge. Arrays are atomic
   *  when using the default `deepMerge`; pass `createUnionMerge()` for element-wise
   *  array union on both push-conflict and pull/ingest. */
  onConflict?: ConflictResolver

  /** Max conflict retry attempts (default: 3) */
  maxRetries?: number

  /**
   * Pre-built encryptor for client-side E2E encryption. For v3 `delegated`
   * collections, build it via `createKeyringEncryptor(keyring, deviceKemKeys)`.
   */
  encryptor?: Encryptor

  /**
   * v3 author-signature plumbing. When set, every push attaches
   * `authorPubkey` (= `cap.sub`) and `authorSignature` (Ed25519 over
   * `stableStringify(payload-without-author-fields)`).
   */
  signer?: SyncSigner

  /** Structured sync event logger */
  logger?: SyncLogger

  /** Label attached to log entries when using a shared logger instance */
  loggerName?: string

  /** Schema validator applied to pulled data before storing locally */
  validate?: Validator
}
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `client` | Yes | — | `StarfishClient` instance |
| `pullPath` | Yes | — | Server path for pull requests |
| `pushPath` | Yes | — | Server path for push requests |
| `onConflict` | No | `deepMerge` | Conflict resolver function |
| `maxRetries` | No | `3` | Max conflict retry attempts |
| `encryptor` | No | — | Pre-built encryptor (v3 keyring path) |
| `signer` | No | — | v3 author-signature provider (`SyncSigner`) |
| `logger` | No | — | Structured sync event logger |
| `loggerName` | No | — | Label for log entries when sharing a logger |
| `validate` | No | — | Schema validator applied to pulled data |

The v2 `signData` hook is removed in 3.0. Use `signer: SyncSigner`
instead — the new hook signs the canonical encrypted payload bytes and
attaches `authorPubkey` / `authorSignature` to the push.

## Methods

### `pull()`

Fetches remote data, decrypts if encryption is enabled, and updates internal state.

```ts
const result = await sync.pull()
console.log(sync.getData())       // the synced document
console.log(sync.getHash())       // server hash
console.log(sync.getCheckpoint()) // last server timestamp (high-water mark)
```

**Behavior:**
- Every pull fetches the **full document** — regular collections no longer support `?checkpoint=` incremental sync (it is now an append-only-only feature). `getCheckpoint()` still returns the last server timestamp as a high-water mark, but it no longer filters the response.
- With encryption: automatically decrypts before storing locally
- The remote document is merged into local data via the configured `onConflict` resolver
  (defaults to `deepMerge`: remote-wins on scalars/arrays, recurse on plain objects)
- **Bootstrap window:** when a store is rebuilt after eviction (e.g. all consumers unmount
  and remount), `seedFromCache()` seeds `localData` from the offline cache but keeps
  `lastCheckpoint` at 0 (so the first pull is a full resync, not a delta). For a
  **custom resolver** (e.g. `createUnionMerge`), that seed is treated as a merge baseline:
  the first `pull()` / `ingest()` after the seed will call `onConflict` against it, so a
  short first-pull response (cache-fallback on 429/5xx, or a momentarily-short concurrent
  snapshot) cannot drop items the resolver is configured to preserve. Stores using the
  default `deepMerge` resolver are unaffected — their first pull still takes the snapshot
  wholesale.

**Returns:** `Promise<PullResult>`

### `push(data)`

Encrypts (if enabled), signs (if a `signer` is configured), and pushes data to the server. Automatically retries on conflict.

```ts
const result = await sync.push({ theme: "dark", lang: "en" })
console.log(result.hash)      // new server hash
console.log(result.timestamp) // server timestamp
```

**Conflict retry loop:**

1. Encrypt data (if `encryptor` configured)
2. Attach `authorPubkey` + `authorSignature` to the encrypted payload (if `signer` configured)
3. Push with current `lastHash`
4. On 409 conflict:
   - Pull latest remote state
   - Call `onConflict(localData, remoteData)` to merge
   - Wait with exponential backoff: `min(100ms * 2^attempt, 2000ms) + random(0-100ms)`
   - Retry (up to `maxRetries` times)
5. Throws `ConflictError` if all retries fail

**Returns:** `Promise<{ hash: string; timestamp: number }>`

### `update(modifier)`

Pull, modify, and push in a single operation.

```ts
await sync.update((current) => ({
  ...current,
  theme: "light",
  updatedAt: Date.now(),
}))
```

Equivalent to:

```ts
await sync.pull()
const updated = modifier(sync.getData())
await sync.push(updated)
```

**Returns:** `Promise<{ hash: string; timestamp: number }>`

### State Accessors

| Method | Returns | Description |
|--------|---------|-------------|
| `getData()` | `Record<string, unknown>` | Current local data snapshot |
| `getHash()` | `string \| null` | Hash of the last known server version |
| `setHash(hash: string \| null)` | `void` | Restore the last-known hash (used by `createStarfishStore` on hydration; consumers using `SyncManager` directly typically do not need this) |
| `getCheckpoint()` | `number` | Timestamp for incremental pulls |

## Encryption (v3 delegated path)

For `encryption: "delegated"` collections, build the encryptor from the
collection's keyring document:

```ts
import {
  SyncManager,
  createKeyringEncryptor,
  type Keyring,
} from "@drakkar.software/starfish-client"

const keyring = (
  await client.pull(`users/${creds.userId}/notes/_keyring`)
).data as Keyring
const encryptor = await createKeyringEncryptor(keyring, {
  kemPubHex: creds.device.kemPub,
  kemPrivHex: creds.device.kemPriv,
})

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${creds.userId}/notes`,
  pushPath: `/push/users/${creds.userId}/notes`,
  encryptor,
})
```

- Data is encrypted before every push and decrypted after every pull.
- The server only sees `{ _encrypted: "base64...", _epoch: N }`.
- The encryptor decrypts any epoch the device has a wrap entry for; it
  encrypts under the keyring's `currentEpoch`.
- See [23. Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated)
  for keyring lifecycle (creation, adding recipients, epoch rotation).

The v2 single-secret `encryptionSecret` / `encryptionSalt` shorthand was removed
in v3 — supply a pre-built `encryptor` (the keyring path above) instead.

## Author Signing

Attach a per-device Ed25519 signature to every push for data provenance.
The `signer.sign` callback signs over the canonical encrypted payload
bytes (`stableStringify(payload-without-author-fields)`), and the manager
inserts `authorPubkey` (= the device's `cap.sub`) and `authorSignature`
into the pushed JSON:

```ts
import { ed25519 } from "@noble/curves/ed25519.js"

const sync = new SyncManager({
  client,
  pullPath,
  pushPath,
  encryptor,
  signer: {
    getSigner: async () => ({
      devEdPubHex: creds.device.edPub,
      sign: async (bytes) =>
        ed25519.sign(bytes, Buffer.from(creds.device.edPriv, "hex")),
    }),
  },
})
```

The server stores `authorPubkey` + `authorSignature` alongside the
encrypted payload, and pull responses surface them so verifying clients
can check that a document was written by a device whose cap was valid at
the time.

## Append-only logs: `AppendLogCursor`

`SyncManager` is for documents you read-merge-write. For **append-only
collections** (a log that only grows, with strictly increasing `ts` per
element), use `AppendLogCursor` instead — the stateful, incremental
counterpart that owns the accumulated log and pulls only what's new:

```ts
import { AppendLogCursor } from "@drakkar.software/starfish-client"

// Cold start → first pull() fetches the whole collection.
// Warm start → seed from persisted data and pull() resumes incrementally.
const log = new AppendLogCursor({
  client,
  pullPath: "/pull/events",
  initialItems: await store.load(), // omit on a cold start
})
const fresh = await log.pull()       // only elements newer than the last held
await store.save(log.getItems())     // persist; the checkpoint is derived from the data
```

It can also decrypt each element (`encryptor`) and verify author signatures
on read (`verifyAuthor`). Unlike `SyncManager`, there is no merge or
push-conflict machinery — a log only grows. See
[Append-only collections](/server/append-only-collections#incremental-cursor-appendlogcursor)
for the full reference.

## Next Steps

- [Encryption](/encryption-identity/encryption) — E2E encryption deep dive
- [Conflict Resolution](/client-core/conflict-resolution) — custom merge strategies
- [Append-only collections](/server/append-only-collections) — `AppendLogCursor`, checkpoints, segmented storage
- [23. Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated) — keyring lifecycle
- [Zustand Binding](/state-offline/state-zustand) — reactive state management on top of SyncManager
