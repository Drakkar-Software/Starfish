# 26. Identity Models

Starfish speaks a **single signature suite on the wire**: Ed25519 for signing,
X25519 for the KEM (key encapsulation). Every cap-cert, request signature,
revocation list, append-author signature, and keyring entry is Ed25519/X25519
— there is no on-wire suite discriminator.

Users with an **external secp256k1 root** (e.g. a Nostr `nsec`, a Bitcoin
wallet, any BIP-340 Schnorr signer) can still bootstrap a Starfish identity:
the caller signs a fixed challenge with their external signer, and Starfish
HKDF-derives the Ed25519 + X25519 seeds from that signature. The secp256k1
root never appears on the wire; the resulting identity is a normal Ed25519
identity from every verifier's perspective.

See [11. Identity & Key Derivation](./11-identity-key-derivation.md) for the
two entry points (passphrase and secp256k1 bootstrap).

## Why ed25519-only?

- Smaller wire format — no suite discriminator in canonical signed inputs.
- Single primitive surface — one library path to audit, one set of test
  vectors, no cross-suite delegation rules.
- Bootstrapping from an external root (secp256k1, FIDO, hardware wallet) is a
  derivation concern, not a wire concern. Adding a new bootstrap source is an
  identities-package change; the protocol stays unchanged.

## Bringing your own secp256k1 root

```ts
import {
  SECP256K1_BOOTSTRAP_CHALLENGE,
  deriveRootIdentityFromSecp256k1Signature,
} from "@drakkar.software/starfish-identities"

// The caller signs SECP256K1_BOOTSTRAP_CHALLENGE (a fixed 32-byte digest)
// with their external BIP-340 Schnorr signer, using deterministic aux_rand=0.
const signature: Uint8Array = await externalSigner.signSchnorr(
  SECP256K1_BOOTSTRAP_CHALLENGE,
  { auxRand: new Uint8Array(32) },
)

const identity = await deriveRootIdentityFromSecp256k1Signature({
  secpPubHex,   // the originating secp256k1 x-only pubkey (BIP-340)
  signature,    // 64-byte deterministic Schnorr signature
})

// `identity.keys` carries the derived Ed25519 + X25519 keys.
// `identity.bootstrapOrigin = { kind: "secp256k1", pubHex: secpPubHex }`
// records the origin for external systems (Nostr-aware UIs, audit logs).
```

The function verifies the signature against `secpPubHex` (catches caller
bugs and makes `bootstrapOrigin` a verifiable claim), then HKDF-SHA256
expands the 64-byte signature into the Ed25519 signing seed and the X25519
KEM seed under domain-separated info strings.

**Determinism contract:** the external signer MUST use deterministic
Schnorr (`aux_rand = 0`). A signer that injects randomness yields a
different identity on every call. Most Schnorr libraries accept an
`aux_rand` argument; pass `new Uint8Array(32)` (TS) / `b"\x00" * 32`
(Python).

## What `bootstrapOrigin` is and isn't

- **Is**: a non-load-bearing metadata field on `RootIdentity` recording the
  originating secp256k1 pubkey. Useful for displaying "this Starfish
  identity is bootstrapped from npub1…" in a UI, or recording it in an
  audit log.
- **Isn't**: signed, transmitted with caps or requests, or load-bearing for
  any verification. The Ed25519 identity stands on its own.

## Cross-language parity

The bootstrap derivation is byte-identical across TypeScript and Python —
locked by `tests/test-vectors/identity-derivation-secp256k1.json`. The same
secp256k1 signature produces the same Ed25519 + X25519 keys (and therefore
the same `userId`) in both runtimes.
