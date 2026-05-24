# starfish-keyring

`@drakkar.software/starfish-keyring` (TS) / `starfish-keyring` (Py) — the multi-recipient encryption layer.

## What it provides

- Keyring document lifecycle: `createKeyring`, `addRecipient`, `rotateEpoch`.
- The encryptor factory: `createKeyringEncryptor` (AES-256-GCM over a per-epoch CEK).
- Per-entry HPKE-DHKEM-style wrap primitives: `wrapForRecipient`, `unwrapFromEntry`, `verifyEntrySignature`.
- Collection-scoped recipient management against a `StarfishClient`: `addCollectionRecipient`, `removeRecipient`, `listRecipients`, `currentEpoch`, `keyringPathFor`.
- Shared low-level crypto helpers reused by `starfish-identities`: `hkdfBytes`, `bytesToHex`, `hexToBytes`, `concat`.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-keyring
```

## Deep-dive docs

The full guides live alongside the client docs (cross-linked here to avoid duplicating content):

- [Encryption model](../client/04-encryption.md)
- [Multi-recipient delegated encryption](../client/23-multi-recipient-delegated.md) — keyring schema, epoch rotation, recipient management, the owner-only `_members` directory.

## Dependency position

```
starfish-protocol ← starfish-keyring ← starfish-identities
```

`starfish-keyring` depends on `starfish-client` (for HTTP I/O) and `starfish-protocol` (types + crypto). The base client/server never import it — the application composes it on top.
