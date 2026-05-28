# EVM-wallet bootstrap of a Starfish root identity — Design Exploration

> Status: exploration. Alpha.13 will ship EIP-191 only; EIP-712 is documented
> here as a forward-locked spec for an alpha.14 follow-up. This document
> compares the EVM-wallet bootstrap options for a Starfish root identity,
> records the alpha.13 decision, and locks the EIP-712 design for alpha.14.

## 1. Background & constraints

Starfish 3.0 identities are an Ed25519 (sign) + X25519 (KEM) key pair plus a short `userId = sha256(edPub)[:32]`. Alpha.12 added a bootstrap path so a user with an existing **secp256k1 (BIP-340 Schnorr) root** — e.g. a Nostr `nsec` — can derive a Starfish identity without exposing the secp256k1 private key:

```
caller signs a fixed 32-byte challenge with their external BIP-340 signer
    ↓ (signature is private-key-equivalent; treated as secret)
verify signature against secpPubHex over the challenge
    ↓
HKDF-SHA256(ikm=signature, salt=…, info=…)  →  ed25519 + x25519 seeds
    ↓
userId = sha256(edPub)[:32]
bootstrapOrigin = { kind: "secp256k1", pubHex }
```

The next major external-root ecosystem to support is **Ethereum / EVM wallets**: MetaMask, ethers.js, viem, WalletConnect, Coinbase Wallet, Trust Wallet, hardware-wallet bridges, MPC wallets. Two canonical message-signing primitives are universally available:

- **EIP-191** (`personal_sign`) — flat UTF-8 string, keccak256 with the `"\x19Ethereum Signed Message:\n<len>"` envelope. Universal support since 2016.
- **EIP-712** (`signTypedData_v4`) — structured typed data, explicit domain separator, generally chain-bound. Modern recommendation; supported across all major wallets.

Both use **secp256k1 ECDSA** under the hood. With **RFC-6979 deterministic** signers, both yield reproducible signatures → suitable for HKDF-based identity derivation, mirroring the alpha.12 path. This is the hard contract the bootstrap path requires.

**Out of scope by design:**
- Non-deterministic ECDSA signers (some older HW firmware, custom HSMs that inject randomness). No detection logic, no double-sign hacks, no "best-effort" fallbacks. If the signer isn't RFC-6979, the caller uses the passphrase path.
- Contract wallets (EIP-1271, Safe, Argent, Sequence) — no recoverable EOA pubkey.
- Signers that pre-process the challenge before signing (rare; e.g. WalletConnect custom transformers).

## 2. Why the same pattern still applies

The BIP-340 derivation has three properties we want to preserve:

1. **No private key leaves the user's signer.** The HKDF input is a signature, not a key.
2. **Reproducible.** Same signer + same challenge → same identity, indefinitely.
3. **Verifiable origin claim.** We verify the signature against the input pubkey before HKDF-expanding, so `bootstrapOrigin` is a verifiable claim, not just a self-asserted label.

EIP-191 and EIP-712 both inherit (1) trivially — the wallet signs, never exports the key. Both inherit (2) iff the signer is RFC-6979 (covered by the contract above). Both inherit (3) iff we ecrecover and compare the recovered address to the input address.

The same downstream invariants apply: HKDF over `signature[0:64]` (drop `v`), domain-separated salt/info per path, ed25519+x25519 seed derivation, `userId = sha256(edPub)[:32]`. Distinct HKDF salts per path ensure the same EVM key yields different Starfish identities depending on which path was used — the bootstrap origin is part of the identity.

## 3. Options

### Option A — EIP-191 `personal_sign`

- **Challenge constant:** `EIP191_BOOTSTRAP_CHALLENGE = "starfish-v3:bootstrap-eip191"` — raw UTF-8 string, 28 bytes. The wallet prepends the EIP-191 envelope itself.
- **Wallet flow:** caller invokes `wallet.personal_sign(challenge)` and receives a 65-byte signature `(r || s || v)`.
- **Envelope** (computed implicitly by every EIP-191 wallet):
  ```
  envelope_bytes = b"\x19Ethereum Signed Message:\n28" + b"starfish-v3:bootstrap-eip191"
  envelope_hash  = keccak256(envelope_bytes)
  ```
- **Verification:** ecrecover `(envelope_hash, r, s, v)` → uncompressed secp256k1 pubkey → derive Ethereum address (`"0x" + keccak256(pubkey_xy_64)[-20:].hex()`) → compare to input address.
- **Seed material:** `signature[0:64]` (drop `v`; it's a 1-bit parity, not entropy; differs in encoding `{0,1}` vs `{27,28}` across wallets, so dropping it removes a normalization choice from the seed namespace).
- **HKDF salts/info:**
  ```
  salt        = "starfish-v3-bootstrap-eip191"
  info(sign)  = "starfish-root-sign:ed25519"
  info(kem)   = "starfish-root-kem:x25519"
  ```

**Pros**
- Universal support: every EVM wallet since 2016.
- Trivial UX: one string challenge, one round-trip.
- Programmatic-friendly: `ethers.Wallet.signMessage(challenge)` / `viem.signMessage({account, message})` — one line in CLI / backend flows where structured-data signing is awkward.
- Mirrors the BIP-340 path structurally (single fixed challenge, no domain knobs).

**Cons**
- Wallet UI shows the raw string. The user sees `"starfish-v3:bootstrap-eip191"` and has limited context. Phishing-resistant only if the challenge is verbose and unmistakably Starfish-branded — mitigated, not fully solved.
- No structured chain binding. A malicious dApp could ask for the same challenge string; mitigated by the challenge constant being Starfish-specific, but the protection is only as strong as the constant's uniqueness.

### Option B — EIP-712 `signTypedData_v4`

- **Domain** (fixed Starfish-bound constants — no `chainId`, no `verifyingContract`, no `salt`):
  ```ts
  domain = { name: "Starfish", version: "3" }
  ```
- **Types:**
  ```ts
  types = {
    Bootstrap: [
      { name: "purpose", type: "string" },
      { name: "version", type: "string" },
    ],
  }
  ```
- **Message:**
  ```ts
  message = { purpose: "bootstrap-root-identity", version: "3" }
  ```
- **Wallet flow:** `wallet.signTypedData(domain, types, message)` → 65-byte signature `(r || s || v)`.
- **Envelope** (per EIP-712 spec):
  ```
  domain_hash  = keccak256(encode(EIP712Domain, domain))
  struct_hash  = keccak256(encode(Bootstrap, message))
  envelope_hash = keccak256("\x19\x01" || domain_hash || struct_hash)
  ```
- **Verification:** ecrecover against `envelope_hash`, compare recovered address to input. Same `r||s` seed material, distinct HKDF salt:
  ```
  salt        = "starfish-v3-bootstrap-eip712"
  info(sign)  = "starfish-root-sign:ed25519"
  info(kem)   = "starfish-root-kem:x25519"
  ```

**Pros**
- Wallet renders **structured fields** in the consent screen ("Domain: Starfish v3 / Bootstrap / purpose: bootstrap-root-identity") — materially better phishing resistance than a flat string.
- Domain separation is built into the protocol — Starfish bootstrap signatures cannot be replayed for any other EIP-712 use even with a colliding message body.
- Modern EVM convention; recommended over EIP-191 for any new app-level signing.

**Cons**
- Slightly more complex envelope; domain hash + struct hash are load-bearing for cross-language vector lock.
- Including `chainId` in the domain would chain-bind the identity (one identity per chain). **Decision: omit `chainId`** — bootstrap identity is chain-agnostic, matching Nostr behavior.
- Marginally less programmatic-friendly than `personal_sign` (typed-data sign requires a typed-data signer, not a raw byte signer).

### Option C — Direct private-key derivation (rejected)

Caller exports the raw Ethereum private key; we HKDF it directly with no signature step.

- ❌ Requires raw key exfiltration — never available from any reputable wallet (MetaMask, Coinbase, HW wallets all refuse to export to dApps).
- ❌ Defeats the central property that the signing key never leaves the wallet.
- ❌ Worse phishing posture than either A or B (the dApp would be asking the user to paste their secret).

**Verdict: rejected.** Same reasoning that rejected the equivalent option for Nostr in alpha.12.

### Option D — EIP-1271 contract wallets (out of scope)

Smart-contract wallets (Safe, Argent, Sequence, etc.) verify signatures via an `isValidSignature(hash, sig)` contract call. The "signature" they return may have no recoverable EOA pubkey at all — it could be a packed multi-sig proof, a session-key witness, or anything else the contract chooses to accept.

- ❌ No entropy source for HKDF: the inner signing material may differ on every call (e.g. session-key rotation) even when the high-level "signature" verifies.
- ❌ No recoverable pubkey to bind `bootstrapOrigin` to.

**Verdict: out of scope.** Future work: bootstrap contract wallets via out-of-band registration of a Starfish-owned ed25519 session key, not via signature-derivation.

### Option E — Non-deterministic HW signers (out of scope)

Hardware wallets with non-RFC-6979 firmware (some older Ledger builds, custom HSMs that inject randomness).

- ❌ Non-reproducible identity → fails property (2).
- ❌ Cannot be detected at first call without a double-sign probe — explicitly vetoed as a "hack".

**Verdict: out of scope by design.** Callers verify their signer is RFC-6979 out-of-band (vendor docs / known-good list) or fall back to the passphrase path.

## 4. Comparison

| Property | A: EIP-191 | B: EIP-712 v4 | C: raw key | D: EIP-1271 | E: non-deterministic HW |
|---|---|---|---|---|---|
| Universal wallet support | ✅ since 2016 | ✅ modern wallets | ❌ never exposed | n/a (different model) | varies |
| Reproducible (RFC-6979) | ✅ in software wallets | ✅ in software wallets | n/a | varies / no | ❌ by definition |
| Phishing resistance | ⚠️ raw string only | ✅ structured render + domain separator | ❌ asking for secret | n/a | n/a |
| Envelope complexity (impl) | trivial | moderate (domain+struct hash) | none | n/a | n/a |
| Chain coupling | none | optional via `chainId` | n/a | n/a | n/a |
| Cross-chain rederive | ✅ | ✅ if `chainId` omitted | n/a | n/a | n/a |
| Programmatic / CLI use | ✅ trivial | ⚠️ typed-data signer needed | n/a | n/a | n/a |
| Inherits BIP-340 properties (1)(2)(3) | ✅ | ✅ | ❌ (1) | ❌ (2)(3) | ❌ (2) |

## 5. Recommendation

**Alpha.13 ships EIP-191 only. EIP-712 is deferred to alpha.14.**

- **Alpha.13: `deriveRootIdentityFromEip191Signature`.** Universal wallet support, trivial UX (single string challenge), trivial implementation (matches the BIP-340 path structurally), one-liner from `ethers` / `viem` / MetaMask. Smaller change surface for the alpha.13 release.
- **Alpha.14 (planned): `deriveRootIdentityFromEip712Signature`.** Better wallet-render UX (structured fields, "Starfish v3 / Bootstrap" in the consent screen instead of a raw string) and free domain-separation replay protection. `chainId` is **omitted** from the domain so the identity is chain-agnostic (one Ethereum key → one Starfish identity, regardless of chain). Full spec lives in §6.2 as forward-locked reference.
- Both functions will live in `packages/{ts,python}/identities`. Distinct HKDF salts ensure the same EVM key produces different Starfish identities per path (`secp256k1` / `eip191` / `eip712`) — the bootstrap origin is part of the identity.

**Why ship EIP-191 first rather than EIP-712.** EIP-712's structured-render benefit matters most in trust-sensitive consent flows (token approvals, swaps). For a one-time identity bootstrap that the user does deliberately at install time, the UX gap between "personal_sign with verbose Starfish challenge" and "signTypedData with structured fields" is much smaller than the implementation gap between the two. Ship the simpler path first; add structured-render later if user feedback flags phishing concerns.

## 6. Pipelines (full byte-level specs)

§6.1 is the **alpha.13 ship spec**. §6.2 is the **alpha.14 forward-locked spec** — documented now so it doesn't lose context, but not implemented yet.

### 6.1 EIP-191 (alpha.13)

```
INPUTS
  address     : str    matches re.fullmatch(r"0x[0-9a-f]{40}", address)
  signature   : bytes  len == 65

CONSTANTS
  EIP191_BOOTSTRAP_CHALLENGE = b"starfish-v3:bootstrap-eip191"   # 28 bytes
  SALT       = b"starfish-v3-bootstrap-eip191"
  INFO_SIGN  = b"starfish-root-sign:ed25519"
  INFO_KEM   = b"starfish-root-kem:x25519"

PIPELINE
  1.  envelope  = b"\x19Ethereum Signed Message:\n28" + EIP191_BOOTSTRAP_CHALLENGE
  2.  digest    = keccak256(envelope)                            # 32 bytes
  3.  r         = signature[0:32]
      s        = signature[32:64]
      v        = signature[64]
  4.  if v >= 27: v -= 27                                         # normalize {27,28} → {0,1}
      assert v in {0, 1}                                          # else reject
  5.  pubkey_xy = secp256k1.ecrecover(digest, r, s, v)            # 64 bytes (X || Y)
  6.  recovered = "0x" + keccak256(pubkey_xy)[-20:].hex()
  7.  if not constant_time_eq(recovered, address): reject "does not verify"
  8.  ikm       = signature[0:64]                                 # drop v from seed material
  9.  ed_seed   = HKDF-SHA256(ikm, salt=SALT, info=INFO_SIGN, L=32)
  10. kem_seed  = HKDF-SHA256(ikm, salt=SALT, info=INFO_KEM,  L=32)
  11. ed_pub    = ed25519.public(ed_seed)
      kem_pub   = x25519.public(kem_seed)
  12. user_id   = sha256(ed_pub).hex()[:32]
  13. zero(ikm-copy)                                              # best-effort wipe
  14. return RootIdentity(user_id, keys, bootstrapOrigin={kind:"eip191", address})
```

### 6.2 EIP-712 (alpha.14, forward-locked)

```
INPUTS
  address     : str    matches re.fullmatch(r"0x[0-9a-f]{40}", address)
  signature   : bytes  len == 65

CONSTANTS
  DOMAIN  = { name: "Starfish", version: "3" }                   # chainId OMITTED
  TYPES   = { Bootstrap: [ {name:"purpose", type:"string"},
                           {name:"version", type:"string"} ] }
  MESSAGE = { purpose: "bootstrap-root-identity", version: "3" }
  SALT       = b"starfish-v3-bootstrap-eip712"
  INFO_SIGN  = b"starfish-root-sign:ed25519"
  INFO_KEM   = b"starfish-root-kem:x25519"

PIPELINE
  1.  domain_type_hash = keccak256(b"EIP712Domain(string name,string version)")
      domain_hash      = keccak256(domain_type_hash
                                   || keccak256(b"Starfish")
                                   || keccak256(b"3"))
  2.  bootstrap_type   = b"Bootstrap(string purpose,string version)"
      struct_type_hash = keccak256(bootstrap_type)
      struct_hash      = keccak256(struct_type_hash
                                   || keccak256(b"bootstrap-root-identity")
                                   || keccak256(b"3"))
  3.  digest  = keccak256(b"\x19\x01" || domain_hash || struct_hash)
  4.  (r, s, v) as in §6.1 step 3-4
  5.  pubkey_xy = secp256k1.ecrecover(digest, r, s, v)
  6.  recovered = "0x" + keccak256(pubkey_xy)[-20:].hex()
  7.  if not constant_time_eq(recovered, address): reject
  8-14. identical to §6.1 steps 8-14 (with the EIP-712 SALT)
```

### 6.3 Shared invariants (both paths)

- **`BootstrapOrigin` becomes a discriminated union** — a breaking change vs the alpha.12 single-shape. Alpha.13 ships the `secp256k1 | eip191` variants; alpha.14 will add `eip712` (additive, not breaking):

  ```ts
  // alpha.13
  type BootstrapOrigin =
    | { kind: "secp256k1"; pubHex: string }
    | { kind: "eip191";    address: string }

  // alpha.14 (planned)
  type BootstrapOrigin =
    | { kind: "secp256k1"; pubHex: string }
    | { kind: "eip191";    address: string }
    | { kind: "eip712";    address: string }
  ```

  Python mirror: dataclass-per-variant + `Union` alias. Alpha.12 was the only release shipping the single-shape; the field is non-load-bearing (never on the wire), so the alpha.13 break is acceptable pre-stable.

- **Address validation uses `re.fullmatch` in Python** to match TS `/^[0-9a-f...]{...}$/.test`. Python `re.match` + trailing `$` accepts a final `\n` and would drift from TS. Same cross-lang gap captured for the secp256k1 path in alpha.12's hardening.
- **`v` normalization:** accept `{0,1}` and `{27,28}` (subtract 27); reject other values. Same normalization both languages.
- **Constant-time address compare** for the recovered-vs-input check (library function, not `==`).
- **Determinism contract restated, loudly, in the function docstring:** the wallet's ECDSA signer MUST use RFC-6979. MetaMask, ethers.js, viem, and modern Trust Wallet builds satisfy this. Hardware wallets — verify out-of-band or fall back to the passphrase path.

## 7. Dependencies

### Alpha.13 (EIP-191 only)

|                              | TypeScript                                                                                  | Python                                                                |
| ---                          | ---                                                                                         | ---                                                                   |
| keccak256                    | **add** `@noble/hashes/sha3.js` (sibling of existing `sha2.js`)                             | **add** `eth-hash[pycryptodome]`                                      |
| secp256k1 ECDSA recover      | existing `@noble/curves/secp256k1.js` (already used for BIP-340 Schnorr verify in alpha.12) | existing `coincurve` (moved to identities in alpha.12)                |

### Alpha.14 (EIP-712, additive)

|                              | TypeScript                                                                  | Python                                                  |
| ---                          | ---                                                                         | ---                                                     |
| EIP-712 hashing helpers      | implement inline using `@noble/hashes/sha3.js` already added in alpha.13    | implement inline using `eth-hash` already added in alpha.13 |

**No new runtime dependencies for the alpha.14 follow-up.** `eth-account` is used **only in the test-vector generator**, not at runtime — same pattern as alpha.12 where `coincurve` is runtime but vector generation used `coincurve.PrivateKey.sign_schnorr`.

## 8. Test plan & cross-language vectors

Mirror the alpha.12 BIP-340 test structure (~16 tests per language per path):

- Challenge (EIP-191) / domain + types (EIP-712) constants equal across TS and Python
- Locked vector cases (≥2 per path)
- Determinism: same input → same output
- Reject 64-byte and 66-byte signatures
- Reject all-zero signature (ecrecover yields *some* address; mismatch input → reject)
- Address validation: missing `0x`, 39 chars, 41 chars, uppercase, **trailing newline** (the cross-lang `fullmatch` test)
- Wrong-address binding: case[0]'s signature + case[1]'s address → reject
- `v` normalization: accept `{0,1}` and `{27,28}`, reject other values
- `bootstrapOrigin` shape: `kind:"eip191"` (alpha.13) / `kind:"eip712"` (alpha.14) + correct address; passphrase path origin still absent

### Cross-language vectors

| | File | Generator | Ships in |
| --- | --- | --- | --- |
| EIP-191 | `tests/test-vectors/identity-derivation-eip191.json` | `_generators/identity_derivation_eip191.py` | alpha.13 |
| EIP-712 | `tests/test-vectors/identity-derivation-eip712.json` | `_generators/identity_derivation_eip712.py` | alpha.14 (planned) |

**Fixture addresses:** the well-known Hardhat default account #0 (`0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`, private key `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`) as case 1, plus a fresh deterministic key as case 2. Generators use `eth-account` (dev-only).

## 9. Risks & considerations

- **Wallet UX variance for EIP-712.** Different wallets render the typed-data screen with subtly different field ordering / styling. Doesn't affect correctness (the hash is canonical), but caller-facing docs should show one screenshot per major wallet (MetaMask + Coinbase Wallet at minimum). Not an alpha.13 concern.
- **`eth-hash` adds a Python sub-dep** (`pycryptodome`). ~2 MB; widely used in the EVM ecosystem; low maintenance risk.
- **`BootstrapOrigin` discriminated-union break.** Alpha.12 consumers reading `origin.pubHex` unconditionally will fail. Acceptable pre-stable; called out in CHANGELOG and migration note.
- **Cross-language EIP-712 hashing.** Domain hash + struct hash must be byte-identical between TS and Python. Risk of subtle drift in keccak / concatenation logic. Mitigated by the lock vector, which exercises every byte of the envelope. Concern for alpha.14, not alpha.13.
- **`chainId` omission is a deliberate design choice.** Some users may expect chain-bound identities (one per chain). Document the alternative (include `chainId`) as an open extension; default to omitted to match the chain-agnostic Nostr behavior. Locking the chain-agnostic choice in the alpha.14 vector means switching to chain-bound later would be a wire-format break.
- **EIP-191 challenge phishing surface.** The challenge constant is Starfish-specific (`"starfish-v3:bootstrap-eip191"`), but a malicious dApp could ask the user to sign the same string. Mitigation: the resulting signature is useless without the Starfish derivation pipeline (the attacker would have to also implement HKDF derivation and convince the user to use the resulting identity). Residual risk is low but documented.
- **Signature is private-key-equivalent.** Same caveat as the BIP-340 path: anyone in possession of the 65-byte EIP-191 signature can reconstruct the full Starfish identity via the public HKDF pipeline. Treat as private-key material — never log, transmit, or persist in cleartext. Derive once, then keep only the resulting identity.

## 10. Open questions

Decisions locked at planning time:

- ✅ Filename: `EVM_BOOTSTRAP_EXPLORATIONS.md` (this file).
- ✅ Alpha.13 scope: **EIP-191 only**; EIP-712 deferred to alpha.14.
- ✅ Non-deterministic signers: out of scope by design — "use a stable feature, not a kind of hack".
- ✅ `verifyEip191SignerIsDeterministic(signFn)` pre-flight helper: **omitted**.

Remaining for the alpha.13 implementation PR:

1. **EIP-191 challenge string finalization** — proposed `"starfish-v3:bootstrap-eip191"`. Should it include a longer human-readable phrase ("Sign this to bootstrap your Starfish identity. This is not a transaction.")? Pro: clearer in the `personal_sign` wallet UI. Con: changes vector inputs and the precise envelope byte length (the `\n28` in step 1 becomes `\n<N>` for some other `N`).
2. **Convenience wrapper** `deriveRootIdentityFromEvmWallet(provider)` — out of scope for alpha.13 (low-level function is the primary surface); revisit in alpha.14 once both paths exist.

Remaining for the alpha.14 (EIP-712) follow-up:

3. **EIP-712 `chainId`** — omit (chain-agnostic, recommended) vs include (chain-bound identities). Document the trade-off in the alpha.14 PR; default is omit.
4. **EIP-712 message body** — keep minimal (`purpose`, `version`) or add a "device-hint" field for caller-supplied context. Default: keep minimal — extra fields would change the canonical envelope and complicate the determinism contract.
