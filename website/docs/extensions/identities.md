---
sidebar_position: 2
sidebar_label: "Identities"
---

# starfish-identities

`@drakkar.software/starfish-identities` (TS) / `starfish-identities` (Py) — root + device identity extension.

## What it provides

- Root identity derivation from a passphrase: `deriveRootIdentity`, `bootstrapRootIdentity` (Argon2id → HKDF → Ed25519 + X25519).
- Bootstrap from an external root without exposing its private key: `deriveRootIdentityFromSecp256k1Signature` (Nostr / BIP-340 Schnorr) and `deriveRootIdentityFromEvmSignature` (EVM wallet / EIP-191). Each verifies a signature over a fixed challenge (`SECP256K1_BOOTSTRAP_CHALLENGE` / `EVM_BOOTSTRAP_CHALLENGE`) and HKDF-derives the Ed25519 + X25519 seeds; the result carries a `bootstrapOrigin` recording the source.
- Device cap-cert minting: `mintDeviceCap` and the `scopes.rootAll()` preset.
- All pairing flows: QR (`buildPairingQr` / `parsePairingQr` / `assemblePairingBundle` / `installPairingBundle`) and server-relay (`buildPairingRequest` / `readPairingRequest` / `buildPairingResponse` / `readPairingResponse`, `deriveCodeKey`).
- The per-user device directory: `addDeviceEntry`, `listDevices`, `removeDeviceEntry`, `devicesPathFor` (the doc at `users/{rootUserId}/_devices`).
- The server plugin: `identitiesServerPlugin` (registers the `device` cap kind).

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-keyring @drakkar.software/starfish-identities
```

(`starfish-keyring` is required transitively — pairing wraps collection CEKs.)

## Server wiring

```ts
import { createCapCertRoleResolver } from "@drakkar.software/starfish-server"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"

const resolver = createCapCertRoleResolver({
  nonceCache, revocationStore,
  plugins: [identitiesServerPlugin],
})
```

## Deep-dive docs

- [Identity & key derivation](/encryption-identity/identity-key-derivation) — root vs device keypairs.
- [Pairing](/encryption-identity/pairing) — bootstrap, QR, and server-relay flows.
- [Capability certificates](/encryption-identity/capability-certs) — cap-cert schema and validation.
