# SyncManager

High-level sync orchestrator that wraps `StarfishClient` with automatic encryption, conflict resolution, retry logic, and state tracking.

> **Prerequisites:** [Getting Started](01-getting-started.md), [StarfishClient](02-starfish-client.md)

## Constructor

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${token}` }),
})

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/settings`,
  pushPath: `/push/users/${userId}/settings`,
})
```

### `SyncManagerOptions`

```ts
interface SyncManagerOptions {
  client: StarfishClient
  pullPath: string
  pushPath: string

  /** Custom conflict resolver. Defaults to remote-wins deep merge. Arrays are atomic. */
  onConflict?: ConflictResolver

  /** Max conflict retry attempts (default: 3) */
  maxRetries?: number

  /** Secret for E2E encryption (enables encryption when set with encryptionSalt) */
  encryptionSecret?: string

  /** Salt for HKDF key derivation */
  encryptionSalt?: string

  /** Info parameter for HKDF (default: "starfish-e2e") */
  encryptionInfo?: string

  /** Callback to sign payloads for data provenance */
  signData?: (data: string) => Promise<string>
}
```

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `client` | Yes | — | `StarfishClient` instance |
| `pullPath` | Yes | — | Server path for pull requests |
| `pushPath` | Yes | — | Server path for push requests |
| `onConflict` | No | `deepMerge` | Conflict resolver function |
| `maxRetries` | No | `3` | Max conflict retry attempts |
| `encryptionSecret` | No | — | Enables E2E encryption |
| `encryptionSalt` | No | — | Salt for key derivation |
| `encryptionInfo` | No | `"starfish-e2e"` | HKDF info parameter |
| `signData` | No | — | Signs the serialized payload |

## Methods

### `pull()`

Fetches remote data, decrypts if encryption is enabled, and updates internal state.

```ts
const result = await sync.pull()
console.log(sync.getData())       // the synced document
console.log(sync.getHash())       // server hash
console.log(sync.getCheckpoint()) // timestamp for incremental pulls
```

**Behavior:**
- First pull (`checkpoint = 0`): fetches the full document
- Subsequent pulls: uses the last checkpoint for incremental sync
- With encryption: automatically decrypts before storing locally
- Without encryption + incremental: deep-merges remote into local data

**Returns:** `Promise<PullResult>`

### `push(data)`

Encrypts (if enabled), signs (if configured), and pushes data to the server. Automatically retries on conflict.

```ts
const result = await sync.push({ theme: "dark", lang: "en" })
console.log(result.hash)      // new server hash
console.log(result.timestamp) // server timestamp
```

**Conflict retry loop:**

1. Encrypt data (if encryption enabled)
2. Sign the serialized payload (if `signData` provided)
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
| `getCheckpoint()` | `number` | Timestamp for incremental pulls |

## Encryption

Pass `encryptionSecret` and `encryptionSalt` to enable client-side E2E encryption:

```ts
const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/notes`,
  pushPath: `/push/users/${userId}/notes`,
  encryptionSecret: "user-generated-secret",
  encryptionSalt: userId,
})
```

- Data is encrypted before every push and decrypted after every pull
- The server only sees `{ _encrypted: "base64..." }`
- See [Encryption](04-encryption.md) for the full crypto design

## Data Signing

Attach a signature to every push for data provenance:

```ts
const sync = new SyncManager({
  client,
  pullPath, pushPath,
  signData: async (data: string) => {
    // `data` is the stable-stringified payload (after encryption, if enabled)
    return await signWithPrivateKey(data)
  },
})
```

The signature is passed as `authorSignature` in the push request. The server can verify it and store `authorPubkey` + `authorSignature` in the pull response.

## Next Steps

- [Encryption](04-encryption.md) — E2E encryption deep dive
- [Conflict Resolution](07-conflict-resolution.md) — custom merge strategies
- [Zustand Binding](05-state-zustand.md) — reactive state management on top of SyncManager
