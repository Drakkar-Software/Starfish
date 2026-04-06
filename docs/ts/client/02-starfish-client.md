# StarfishClient

Low-level HTTP client for the Starfish sync protocol. Handles authentication, request formatting, and response parsing.

> **Prerequisites:** [Getting Started](01-getting-started.md)

## Constructor

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async (req) => ({ Authorization: `Bearer ${token}` }),
})
```

### `StarfishClientOptions`

```ts
interface StarfishClientOptions {
  /** Base URL of the Starfish server (e.g. "https://api.example.com/v1") */
  baseUrl: string
  /** Auth provider that returns headers for authenticated requests */
  auth?: AuthProvider
  /** Custom fetch implementation (defaults to global fetch) */
  fetch?: typeof fetch
}
```

## Auth Providers

The `AuthProvider` receives request metadata and returns headers:

```ts
type AuthProvider = (req: {
  method: string
  path: string
  body: string | null
}) => Record<string, string> | Promise<Record<string, string>>
```

### Bearer token

```ts
auth: async () => ({
  Authorization: `Bearer ${await getToken()}`,
})
```

### API key

```ts
auth: () => ({
  "X-API-Key": apiKey,
})
```

### Request signature

The `method`, `path`, and `body` parameters enable request signing:

```ts
auth: async (req) => {
  const payload = `${req.method}:${req.path}:${req.body ?? ""}`
  const signature = await sign(payload, privateKey)
  return {
    "X-Public-Key": publicKey,
    "X-Signature": signature,
  }
}
```

## Methods

### `pull(path, checkpoint?)`

Fetches synced data from the server.

```ts
const result = await client.pull(`/pull/users/${userId}/settings`)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | `string` | Server endpoint path |
| `checkpoint` | `number` | Optional. Timestamp for incremental pull. `0` or omitted = full pull |

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
Authorization: Bearer {token}
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
Authorization: Bearer {token}
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
  fetch: myCustomFetch,
})
```

## Next Steps

- [SyncManager](03-sync-manager.md) — wraps `StarfishClient` with encryption, conflict retry, and state tracking
- [Encryption](04-encryption.md) — E2E encryption details
- [Error Classification & Retry](15-error-retry.md) — retry wrapper and circuit breaker via custom `fetch`
- [Logging & Observability](16-logging-observability.md) — request logging via custom `fetch`
