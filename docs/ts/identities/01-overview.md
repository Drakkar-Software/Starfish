# starfish-identities

`@drakkar.software/starfish-identities` (TS) / `starfish-identities` (Py) — root + device identity extension.

## What it provides

- Root identity derivation from a passphrase: `deriveRootIdentity`, `bootstrapRootIdentity` (Argon2id → HKDF → Ed25519 + X25519).
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

- [Identity & key derivation](../client/11-identity-key-derivation.md) — root vs device keypairs.
- [Pairing](../client/24-pairing.md) — bootstrap, QR, and server-relay flows.
- [Capability certificates](../client/25-capability-certs.md) — cap-cert schema and validation.
