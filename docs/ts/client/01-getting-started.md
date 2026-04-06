# Getting Started

Get from zero to a working pull/push sync in under 2 minutes.

> **Prerequisites:** A running Starfish server.

## Installation

```bash
npm install @drakkar.software/starfish-client
```

## First Sync — Low-Level

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${token}` }),
})

// Pull current state
const result = await client.pull(`/pull/users/${userId}/settings`)
// => { data: { theme: "light" }, hash: "a1b2c3...", timestamp: 1712345678 }

// Push an update (baseHash = current hash for conflict detection)
const updated = { ...result.data, theme: "dark" }
const success = await client.push(
  `/push/users/${userId}/settings`,
  updated,
  result.hash,
)
// => { hash: "d4e5f6...", timestamp: 1712345679 }
```

`pull()` returns a `PullResult` (simplified — see [StarfishClient](02-starfish-client.md) for the full type):

```ts
interface PullResult {
  data: Record<string, unknown>
  hash: string
  timestamp: number
}
```

`push()` returns a `PushSuccess`:

```ts
interface PushSuccess {
  hash: string
  timestamp: number
}
```

## Upgrade to SyncManager

For automatic conflict resolution, encryption, and state tracking, wrap the client in a `SyncManager`:

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

// Pull, modify, push — conflicts are retried automatically
await sync.pull()
console.log(sync.getData()) // { theme: "light" }

await sync.push({ theme: "dark", lang: "en" })
console.log(sync.getHash()) // "d4e5f6..."

// Or do it all in one call
await sync.update((current) => ({ ...current, theme: "light" }))
```

## Add Encryption

Pass `encryptionSecret` and `encryptionSalt` — data is encrypted before push and decrypted after pull. The server never sees plaintext.

```ts
const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/notes`,
  pushPath: `/push/users/${userId}/notes`,
  encryptionSecret: "user-generated-secret",
  encryptionSalt: userId,
})

await sync.push({ items: ["note 1", "note 2"] })
// Server stores: { _encrypted: "base64..." }
```

## Next Steps

- [StarfishClient](02-starfish-client.md) — full low-level API reference
- [SyncManager](03-sync-manager.md) — encryption, conflict resolution, signing
- [Zustand Binding](05-state-zustand.md) — reactive state for React apps
- [Legend State Binding](06-state-legend.md) — fine-grained observable state
