# 26. Identity Models (Crypto Suites)

Starfish identities are **pluggable**. Each identity picks a *crypto suite* — the
signature scheme (and KEM) behind its keys — identified by an `alg` tag. Two
suites ship today, and they can coexist in one deployment **per user**.

| Suite | Signing | KEM (encryption) | Encoding | Status |
|---|---|---|---|---|
| `ed25519` (default) | Ed25519 | X25519 (separate key) | hex | full |
| `secp256k1-schnorr` ("Nostr") | BIP-340 Schnorr / secp256k1 | secp256k1 ECDH (same key) | hex | sign + KEM |

> **Scope note.** As of 3.0.0-alpha.4 the `secp256k1-schnorr` suite implements
> **both signing and the KEM** (secp256k1 ECDH for the per-collection keyring):
> a `secp256k1-schnorr` identity can sign cap-certs/requests **and** be a
> recipient of `delegated`-encrypted collection keys, and a secp256k1 owner can
> grant/manage keyring access. Still deferred to the bring-your-own-nsec phase:
> **multi-device pairing** for a secp256k1 root (the pairing bundle wrap is still
> X25519-only, and secp256k1 *root creation* — passphrase derivation is
> `ed25519`-only today — does not exist yet), plus npub/nsec (bech32) encoding
> and NIP-06 derivation. So a secp256k1 identity is a bring-your-own-key
> recipient/member today, not yet a passphrase-derived root with its own devices.

> **Interop note.** "Nostr" here means the *key type* (secp256k1 x-only) and the
> ECDH *primitive* — not wire compatibility. Starfish signatures are over
> `sha256(canonical Starfish bytes)`, **not** NIP-01 event ids, and the keyring
> wrap uses Starfish's own HKDF (`salt="starfish-wrap"`, suite-tagged info),
> **not** NIP-44's `conversation_key`/per-message nonce. So you can bring a
> secp256k1 keypair, but a stock Nostr client cannot verify a Starfish signature
> or unwrap a Starfish-encrypted collection key. Full npub/nsec + NIP-44 interop
> is out of scope for this suite.

## Where the suite lives

The suite is carried explicitly so verifiers never guess a curve:

- **Cap-certs** carry `issAlg` (issuer), optional `subAlg` (subject signing),
  and optional `subKemAlg` (subject KEM). See
  [Capability Certificates](./25-capability-certs.md).
- **Request signatures** carry `alg`, sent on the wire as the `X-Starfish-Alg`
  header alongside `X-Starfish-Sig` / `-Ts` / `-Nonce`.
- **Revocation lists** carry `alg` (the issuer's suite).

In every case the `alg` is folded into the **signed canonical bytes**, so an
attacker cannot strip or downgrade the suite without invalidating the signature.

## Choosing a suite

```ts
import { mintDeviceCap } from "@drakkar.software/starfish-identities"

// Default (ed25519) — unchanged from earlier alphas:
await mintDeviceCap(issPrivHex, issPubHex, sub, scope)

// Opt a subject into the Nostr suite (issuer stays ed25519 by default):
await mintDeviceCap(issPrivHex, issPubHex, sub, scope, { subAlg: "secp256k1-schnorr" })
```

`alg` is the **issuer** suite (governs the cap signature); `subAlg` is the
**subject** suite (governs the subject's keys and its per-request signatures).
Omit `subAlg` to use the same suite as the issuer.

## Cross-suite delegation

Because issuer and subject suites are independent, an `ed25519` root can grant a
`member` cap to a `secp256k1-schnorr` user:

- the cap's `sig` verifies under `issAlg = ed25519`;
- the member's per-request signatures verify under `subAlg = secp256k1-schnorr`.

The server resolves the request-signature suite authoritatively from the
verified `cert.subAlg` for device/member caps; for `audience` (public-link)
caps, where each redeemer brings their own key, it reads the `X-Starfish-Alg`
header (validated; defaults to `ed25519`).

## Signing vs KEM suite: `subAlg` and `subKemAlg`

A subject's **signing** suite (`subAlg`) and **KEM** (encryption) suite
(`subKemAlg`) are independent. `subKemAlg` is optional and defaults to `subAlg`;
it is emitted only when a caller opts into a decoupled KEM suite. The keyring
wraps under **any** registered suite's KEM (resolved via `recipientKem(cert)`),
so every combination below is mintable and wrappable:

- **Pure `secp256k1-schnorr`** — sign and receive encrypted keys under one
  secp256k1 key (the Nostr convention; no separate `subKem`).
- **`secp256k1-schnorr` signing + `ed25519` (X25519) KEM** — sign with your
  Nostr key, receive encrypted collection keys under a clean X25519 key.
- **`ed25519` signing + `secp256k1-schnorr` KEM** — sign with a clean Ed25519
  key, receive encrypted keys under a Nostr-curve KEM. A future post-quantum or
  pure-KEM suite would reuse the same wrap/HKDF plumbing, but — because `Alg` is
  today a *signing*-suite tag with a 1:1 sign↔KEM mapping — it would additionally
  require splitting a separate `KemAlg` enum (or making suite lookup role-aware).
  See the CHANGELOG "KEM-phase contracts" forward-contract (3).

`subKem` (the KEM pubkey) is **present unless the KEM key is the signing key** —
omitted only when `subKemAlg == subAlg` *and* that suite reuses one key
(`secp256k1-schnorr`). So an `ed25519` subject carries a distinct X25519
`subKem`; a same-suite `secp256k1-schnorr` subject omits it (its `sub` *is* the
KEM key); any mixed pair carries a distinct `subKem` of suite `subKemAlg`.
Well-formedness enforces this in both languages; `recipientKem(cert)` returns the
`{ kemPubHex, kemAlg }` the keyring seals to.

## Determinism & cross-language parity

Both suites are deterministic and produce byte-identical signatures across the
TypeScript and Python implementations:

- `ed25519` — RFC 8032 (deterministic by construction).
- `secp256k1-schnorr` — signs `sha256(message)` with `aux_rand = 0` (BIP-340
  permits this), proven identical between `@noble/curves` (TS) and `coincurve`
  (Python). See `tests/test-vectors/suite-secp256k1.json`.
- `secp256k1-schnorr` **KEM** — the ECDH shared secret is the x-coordinate of
  `priv·lift_even(peerXOnly)`, parity-free and ECDH-symmetric, byte-identical
  across both libraries. See `tests/test-vectors/suite-secp256k1-ecdh.json` and
  the keyring wrap vector `tests/test-vectors/keyring-wrap-secp256k1.json`.

## Library notes

- **TypeScript** is edge-safe everywhere: `@noble/curves` is pure-JS.
- **Python** needs the `coincurve` (libsecp256k1) C extension only for the
  `secp256k1-schnorr` suite; it is imported lazily, so an `ed25519`-only Python
  deployment (e.g. a restricted serverless target) does not require it. A
  `secp256k1-schnorr` signature on a deployment without `coincurve` fails closed
  (verification returns `false`), it does not crash.

## Security hygiene note

A same-suite `secp256k1-schnorr` identity reuses one secp256k1 key for both
Schnorr signing and ECDH — the Nostr convention. This is a deliberate trade for
ecosystem compatibility; `ed25519`'s separate signing/KEM keys remain the more
conservative default. If you want the Nostr signing identity without the
key-reuse, mint with `subAlg: "secp256k1-schnorr"` + `subKemAlg: "ed25519"` — a
distinct X25519 `subKem` is then emitted and the keyring seals under X25519.
