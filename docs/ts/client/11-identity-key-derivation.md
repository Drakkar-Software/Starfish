# Identity & Key Derivation

Starfish 3.0 binds every user to a **root key pair** derived deterministically from a passphrase. The root key signs capability certificates (cap-certs); each device runs under its own per-device key pair authorized by such a cert.

> **Prerequisites:** [StarfishClient](02-starfish-client.md), [Encryption](04-encryption.md), [Capability Certificates](25-capability-certs.md)

## Root identity

A user's root identity consists of:

| Field | Type | Purpose |
|-------|------|---------|
| `userId` | 32 hex chars | First 32 hex chars of `sha256(rootEdPub)`. Stable across devices. Used in URL paths via `{identity}`. |
| `keys.edPriv` / `keys.edPub` | 64-char lowercase hex (Ed25519) | Signs cap-certs, the revocation list, and (on the first device only) authenticates requests. |
| `keys.kemPriv` / `keys.kemPub` | 64-char lowercase hex (X25519) | Unwraps keyring entries. The root pubkey doubles as the first device's KEM pubkey. |

All four key fields are 32-byte values rendered as 64-character lowercase hex strings.

### Derivation

```
master      = Argon2id(password = utf8(passphrase),
                       salt     = utf8("starfish-v3-root"),
                       m = 47104 KiB, t = 3, p = 1,
                       len = 32)                  ← memory-hard password stretch

rootEdSeed  = HKDF-SHA256(ikm  = master,
                          salt = utf8("starfish-root-sign"),
                          info = utf8("ed25519"),
                          len  = 32)
rootEdPub   = Ed25519.publicKey(rootEdSeed)

rootKemSeed = HKDF-SHA256(ikm  = master,
                          salt = utf8("starfish-root-kem"),
                          info = utf8("x25519"),
                          len  = 32)
rootKemPub  = X25519.publicKey(rootKemSeed)

userId      = hex(sha256(rootEdPub))[0:32]
```

The derivation is a two-stage chain. **Stage 1 — Argon2id** (memory-hard, `m=47104 KiB ≈ 46 MiB, t=3, p=1`, fixed UTF-8 salt `"starfish-v3-root"`) stretches the passphrase into a 32-byte `master` secret. This is the brute-force gate: it raises the offline cost for low-entropy passphrases far above a plain hash. The salt is global (not per-user) so the same passphrase yields the same identity on every device. **Stage 2 — HKDF-SHA256** expands `master` into two domain-separated seeds. The two independent HKDF derivations give complete domain separation between the signing and KEM key — a compromise of one (or future cryptanalysis against one curve) does not leak the other. The Ed25519 seed and the X25519 scalar both come out of HKDF directly; `@noble/curves` clamps the X25519 scalar internally during point multiplication. `deriveRootIdentity` zeroes `master` once both seeds are derived.

The Argon2id parameters are locked (`ARGON2_PARAMS` in `starfish-identities`) — changing them changes every derived identity, so they are pinned by the cross-language test vectors below.

Cross-language test vectors lock the derivation: [`tests/test-vectors/identity-derivation.json`](../../../tests/test-vectors/identity-derivation.json). Both the TypeScript and Python implementations must produce byte-identical seeds and `userId` values for every fixture.

### `deriveRootIdentity(passphrase)`

```ts
import { deriveRootIdentity } from "@drakkar.software/starfish-client"

const root = await deriveRootIdentity("paragraph-loud-yarn-river-cabin-tundra")
// root = {
//   userId: "cc99505e6697f7ac",
//   keys: { edPriv, edPub, kemPriv, kemPub },   // all 64-char hex
// }
```

This is the lower-level primitive: it returns just the key material. It does **not** mint a cap-cert or set up any device state. Use it when you need the keys for an ad-hoc operation (re-signing a revocation list, granting a member cap, recovering a userId from a passphrase, etc.).

## Bootstrap: passphrase → ready-to-use device

For the first device of a user, `bootstrapRootIdentity` runs `deriveRootIdentity` and then self-signs a full-scope `kind: "device"` cap-cert. The returned device pair **is** the root pair on the first device — there is no separate per-device key on a brand-new account.

```ts
import { bootstrapRootIdentity } from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity("paragraph-loud-yarn-river-cabin-tundra")
// creds = {
//   rootEdPub,                                    // hex
//   userId,                                       // hex 32
//   device: { edPriv, edPub, kemPriv, kemPub },   // hex; equals the root keys here
//   capCert,                                      // self-signed kind:"device" full-scope cap
// }
```

After bootstrap, plug `creds` into a `StarfishClient` `capProvider` and a `SyncManager` `signer`. See [25. Capability Certificates](25-capability-certs.md) for the cap-cert schema and [03. SyncManager](03-sync-manager.md) for the `signer` interface.

## Per-device identities

Every device added after the first one runs under **freshly generated** Ed25519 + X25519 key pairs — they are not derived from the passphrase.

```ts
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

function generateDeviceKeys() {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPriv:  hex(edPriv),
    edPub:   hex(ed25519.getPublicKey(edPriv)),
    kemPriv: hex(kemPriv),
    kemPub:  hex(x25519.getPublicKey(kemPriv)),
  }
}
```

Why generate locally instead of deriving from the passphrase?

- The per-device key never has to leave the device — not even encrypted in the keyring. A passphrase-derived device key would be re-derivable on any other device that learned the passphrase, defeating the per-device compromise boundary.
- Revoking a device means revoking *its* cap-cert. With a derived key the same key reappears on the next bootstrap; with a generated key revocation is final.
- Per-device generated keys are what makes [24. Pairing](24-pairing.md) meaningful: the new device shows its freshly-generated pubkey in the QR / relay request; the root device mints a cap-cert binding that pubkey.

## userId stability

`userId` is a function of the root Ed25519 public key alone. It is stable across:

- The same passphrase on any device.
- Cap-cert rotations (the cert changes; `iss` and `issUserId` do not).
- Per-device key changes (only the root key drives `userId`).

It changes only if the user changes their passphrase. There is no separate `encryptionSalt` — the keyring's per-entry ephemeral ECDH makes a global salt unnecessary.

## Encoding conventions

| Value | Encoding |
|-------|----------|
| Any 32-byte key (Ed25519 priv/pub, X25519 priv/pub, CEK) | 64-char **lowercase** hex |
| Cap-cert signatures, AES-GCM ciphertext, nonces | standard base64 (padded) |
| `userId` | first 32 chars of `hex(sha256(rootEdPub))` — lowercase hex |

Lowercase hex is canonical. Mixed-case input is not accepted by the wire-format validators.

## Next Steps

- [25. Capability Certificates](25-capability-certs.md) — minting `device` and `member` caps with these keys
- [24. Pairing](24-pairing.md) — bootstrap, QR pairing, server-relay invite
- [04. Encryption](04-encryption.md) — how the X25519 KEM key feeds the per-collection keyring
- [10. Platform Setup](10-platform-setup.md) — crypto provider configuration for React Native
