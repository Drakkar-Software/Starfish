---
sidebar_position: 4
---

# WAL Client Adapters (`@drakkar.software/starfish-wal/client`)

The `starfish-wal` package ships the CRDT engine and injection interfaces
(`WalTransport`, `WalSnapshotStore`, `WalEncryptor`, `WalSigner`) but not the
live-network wiring. Import from the `/client` subpath to get the canonical
adapters that connect those interfaces to a `StarfishClient`.

The subpath is intentionally separate so apps that do **not** use WAL documents
can exclude `starfish-client` from their `starfish-wal` bundle.

## Quick start

```ts
import { createWalDocument } from "@drakkar.software/starfish-wal/client"

const doc = createWalDocument({
  client,                           // any StarfishClient instance
  documentKey: "spaces/sp-123/pages/pg-456",
  edPubHex: device.edPubHex,
  edPrivHex: device.edPrivHex,
  encryptor: spaceKeyring,          // omit or null for plaintext
})

await doc.open()
doc.dispatch([{ type: "set", path: ["title"], value: "Hello" }])
```

## `createWalDocument` options

```ts
interface CreateWalDocumentOptions {
  /** A StarfishClient instance (or any object with pull/push/append). */
  client: WalStarfishClient
  /** Storage key without /push/ or /pull/ prefixes.
   *  e.g. "spaces/{spaceId}/objects/pages/{objectId}" */
  documentKey: string
  /** Device's Ed25519 signing public key (hex). */
  edPubHex: string
  /** Device's Ed25519 signing private key (hex). */
  edPrivHex: string
  /** Keyring Encryptor for delegated-encryption spaces.
   *  Omit or null for plaintext — noopEncryptor is used automatically. */
  encryptor?: { encrypt: (...) => Promise<...>; decrypt: (...) => Promise<...> } | null
  /** Per-session nonce for multi-tab disambiguation. */
  sessionNonce?: string
  /** Enable snapshot document for fast cold-start. Default true. */
  withSnapshots?: boolean
  /** Reader posture for gap handling. Default "trust-retain-tail". */
  posture?: ReaderPosture
}
```

## Individual adapters

If you need finer control, use the adapters individually:

### `createWalTransport(client)`

Wires `WalTransport` to `StarfishClient.append` (write) and `StarfishClient.pull`
with `AppendPullOptions` (read). A 404 on read is treated as an empty document
rather than an error.

### `createWalSnapshotStore(client)`

Wires `WalSnapshotStore` to a sibling LWW document at `<documentKey>__snapshot`.
Uses hash-CAS push with up to 3 retry attempts on conflict.

### `walSignerFromKeys(edPubHex, edPrivHex)`

Alias for `createEd25519Signer` — builds a `WalSigner` from a device keypair.
Uses the same `signAppendAuthor` / `signDocAuthor` primitives as
`StarfishClient.append`, so author proofs produced by the WAL are byte-identical
to those the HTTP layer signs automatically.

### `walEncryptorFromKeyring(encryptor)`

Adapts a keyring `{encrypt, decrypt}` encryptor (from `createKeyringEncryptor`)
to the WAL `{seal, open}` interface.

### `noopEncryptor`

Pass-through encryptor for plaintext collections — `seal(x) === open(x) === x`.
Re-exported from the `/client` subpath for convenience.

## Architecture diagram

```
StarfishClient.append("/push/<key>", element)
       ↑
WalTransport.append ─────────────────────────────────────────────┐
                                                                  │
WalDocument ─── dispatch(ops) ─── sign(ops) ─── seal(ops) ──────►│
                                                                  │
WalTransport.pull("/pull/<key>", since) ◄── StarfishClient.pull ─┘
       │
       ▼
WalDocument ─── unseal(elements) ─── verify(author) ─── apply(CRDT)
       │
       ▼
WalSnapshotStore.write("<key>__snapshot") ◄── StarfishClient.push (CAS)
```

## Snapshot document

When `withSnapshots: true` (default), `createWalDocument` wires a sibling snapshot
document at `<documentKey>__snapshot`. This is a regular LWW (last-write-wins)
document that compacts the WAL state for fast cold-starts — opening a large WAL doc
no longer replays every element from epoch 0.

The snapshot is written asynchronously in the background after open; it does not
block the first dispatch. The snapshot doc carries a `producedBy` + author signature
so readers can verify it was produced by a legitimate replica.

## TypeScript types

```ts
// Minimal client surface — the real StarfishClient satisfies this interface.
interface WalStarfishClient {
  pull(path: string, opts?: Record<string, unknown>): Promise<any>
  push(path: string, data: Record<string, unknown>, baseHash: string | null): Promise<any>
  append(path: string, data: Record<string, unknown>): Promise<{ timestamp: number }>
}
```

The `WalStarfishClient` interface is intentionally minimal so the WAL client module
does not depend on `starfish-client` at runtime — adapters compose structurally.
