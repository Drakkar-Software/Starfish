---
sidebar_position: 1
---

# Getting Started

Get from zero to a working pull/push sync in under 2 minutes.

> **Prerequisites:** A running Starfish server.

## Installation

```bash
npm install @drakkar.software/starfish-client
```

## First Sync — Low-Level

```ts
import {
  StarfishClient,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"

// One-time at startup: derive the user's root identity + self-signed device
// cap-cert from a passphrase. Persist `creds` to local storage so it survives
// process restarts.
const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// Pull current state. `creds.userId` is the v3 short userId
// (`sha256(rootEdPub)[0:32]`).
const result = await client.pull(`/pull/users/${creds.userId}/settings`)
// => { data: { theme: "light" }, hash: "a1b2c3...", timestamp: 1712345678 }

// Push an update (baseHash = current hash for conflict detection)
const updated = { ...result.data, theme: "dark" }
const success = await client.push(
  `/push/users/${creds.userId}/settings`,
  updated,
  result.hash,
)
// => { hash: "d4e5f6...", timestamp: 1712345679 }
```

`pull()` returns a `PullResult` (simplified — see [StarfishClient](/client-core/starfish-client) for the full type):

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
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${creds.userId}/settings`,
  pushPath: `/push/users/${creds.userId}/settings`,
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

Starfish 3.0 has one client-side encryption mode: `"delegated"` — N-recipient
multi-device / group encryption backed by a sibling keyring document. Build
an `Encryptor` via `createKeyringEncryptor` from the collection keyring and
pass it to `SyncManager`. The server never sees plaintext.

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

await sync.push({ items: ["note 1", "note 2"] })
// Server stores: { _encrypted: "base64...", _epoch: 1 }
```

The first device on a collection seeds the keyring with `createKeyring(...)`
and pushes it. Subsequent devices are added as recipients via
`addCollectionRecipient` (or assembled into the keyring as part of pairing).
See [23. Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated)
for the full algorithm.

## Next Steps

- [StarfishClient](/client-core/starfish-client) — full low-level API reference
- [SyncManager](/client-core/sync-manager) — encryption, conflict resolution, signing
- [11. Identity & Key Derivation](/encryption-identity/identity-key-derivation) — `bootstrapRootIdentity`, cap-certs
- [23. Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated) — keyring shape, recipient helpers
- [24. Pairing](/encryption-identity/pairing) — QR and relay flows for additional devices
- [Zustand Binding](/state-offline/state-zustand) — reactive state for React apps
- [Legend State Binding](/state-offline/state-legend) — fine-grained observable state
