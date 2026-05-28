import { getCrypto } from "@drakkar.software/starfish-protocol"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { schnorr } from "@noble/curves/secp256k1.js"
import { sha256 } from "@noble/hashes/sha2.js"
import { argon2id } from "hash-wasm"

import { bytesToHex, hexToBytes, hkdfBytes } from "@drakkar.software/starfish-keyring"

// ── v3 root-identity types ────────────────────────────────────────────────────

/**
 * Root key material derived from a passphrase. All keys are 32 bytes,
 * encoded as 64-character lowercase hex strings.
 *
 * - `edPriv` / `edPub`: Ed25519 signing key pair (used for signing cap-certs
 *   and authenticating requests).
 * - `kemPriv` / `kemPub`: X25519 key encapsulation key pair (used for wrapping
 *   secrets to a recipient).
 */
export interface RootKeyPair {
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
}

/**
 * Non-load-bearing origin metadata recording how a root identity was derived.
 * Never appears on the wire (caps, request signatures, keyring entries) — it
 * exists only for external systems (e.g. Nostr-aware UIs, audit logs) to display
 * the bootstrap source. Absent on passphrase-derived identities.
 */
export type BootstrapOrigin = {
  kind: "secp256k1"
  /** Originating secp256k1 x-only pubkey (64-char lowercase hex). */
  pubHex: string
}

/**
 * A v3 root identity: the deterministic Ed25519 + X25519 key pairs and the short
 * `userId` derived from the Ed25519 public key. Optionally carries a
 * {@link BootstrapOrigin} when the identity was derived from an external root.
 */
export interface RootIdentity {
  /** First 32 hex chars (16 bytes) of `sha256(rootEdPub)`. */
  userId: string
  /** Root Ed25519 (signing) and X25519 (KEM) key pairs as hex. */
  keys: RootKeyPair
  /** Bootstrap origin (e.g. secp256k1 root). Absent for passphrase-derived identities. */
  bootstrapOrigin?: BootstrapOrigin
}

// ── v3 root-identity derivation ───────────────────────────────────────────────
//
// Two-stage chain:
//   master = Argon2id(passphrase, ARGON2_SALT, params)      ← password-stretch
//   edSeed = HKDF-SHA256(master, "starfish-root-sign", "ed25519")
//   kemSeed = HKDF-SHA256(master, "starfish-root-kem", "x25519")
//
// Argon2id (memory-hard) raises offline brute-force cost for low-entropy
// passphrases. These params (m=47104 KiB ≈ 46 MiB, t=3, p=1) sit above the
// OWASP interactive-login minimum (m=19456, t=2): a root identity — and a
// passphrase-sealed envelope carrying private device keys — is a higher-value,
// longer-lived secret than a session login. HKDF then expands the stretched
// master into domain-separated subkeys without further work — Argon2 is the gate.

/** Locked Argon2id parameters. Changing these requires regenerating every
 *  cross-language test vector that uses a fixture root identity, and updating
 *  the hardcoded fixture key in cap-verify.test.ts / test_cap_verify.py. */
export const ARGON2_PARAMS = {
  memoryKiB: 47_104,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
  /** UTF-8 salt — global, not per-user (root derivation must be deterministic
   *  for the same passphrase across devices). */
  saltUtf8: "starfish-v3-root",
} as const

const ROOT_ED_HKDF_SALT = "starfish-root-sign"
const ROOT_ED_HKDF_INFO = "ed25519"
const ROOT_KEM_HKDF_SALT = "starfish-root-kem"
const ROOT_KEM_HKDF_INFO = "x25519"

// Bootstrap-from-secp256k1: separate salt so a secp256k1 root can never collide
// with a passphrase whose Argon2id-stretched master happens to equal the
// signature bytes used as IKM here. The info strings are also distinct from the
// passphrase path's bare `"ed25519"` / `"x25519"` for extra paranoia.
const BOOTSTRAP_SECP_HKDF_SALT = "starfish-v3-bootstrap-secp256k1"
const BOOTSTRAP_SECP_SIGN_INFO = "starfish-root-sign:ed25519"
const BOOTSTRAP_SECP_KEM_INFO = "starfish-root-kem:x25519"

/**
 * Fixed 32-byte challenge the caller's secp256k1 signer must sign to bootstrap
 * an identity. SHA-256 of the literal `b"starfish-v3:bootstrap-secp256k1"`,
 * which keeps the challenge exactly 32 bytes (the size BIP-340 Schnorr signs).
 * Byte-identical across TS and Python — locked by
 * `tests/test-vectors/identity-derivation-secp256k1.json`.
 */
export const SECP256K1_BOOTSTRAP_CHALLENGE: Uint8Array = sha256(
  new TextEncoder().encode("starfish-v3:bootstrap-secp256k1"),
)

async function argon2idStretch(passphrase: string): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const result = await argon2id({
    password: passphrase,
    salt: enc.encode(ARGON2_PARAMS.saltUtf8),
    parallelism: ARGON2_PARAMS.parallelism,
    iterations: ARGON2_PARAMS.iterations,
    memorySize: ARGON2_PARAMS.memoryKiB,
    hashLength: ARGON2_PARAMS.hashLength,
    outputType: "binary",
  })
  return new Uint8Array(result)
}

async function userIdFromEdPub(edPubBytes: Uint8Array): Promise<string> {
  const c = getCrypto()
  const pubHash = await c.subtle.digest("SHA-256", edPubBytes as BufferSource)
  return bytesToHex(new Uint8Array(pubHash)).slice(0, 32)
}

/**
 * Derives a v3 root identity from a passphrase.
 *
 * Pipeline: Argon2id (memory-hard password stretch) → HKDF-SHA256 (expand into
 * Ed25519 + X25519 seeds) → public key derivation → userId. The Ed25519 public
 * key is hashed (SHA-256) and the first 32 hex characters become the `userId`.
 *
 * @param passphrase The user's passphrase. Must be non-empty.
 */
export async function deriveRootIdentity(passphrase: string): Promise<RootIdentity> {
  if (!passphrase.trim()) throw new Error("Passphrase must not be empty")

  const master = await argon2idStretch(passphrase)
  const enc = new TextEncoder()
  const edSeed = await hkdfBytes(
    master,
    enc.encode(ROOT_ED_HKDF_SALT),
    enc.encode(ROOT_ED_HKDF_INFO),
    32,
  )
  const edPubBytes = ed25519.getPublicKey(edSeed)

  const kemSeed = await hkdfBytes(
    master,
    enc.encode(ROOT_KEM_HKDF_SALT),
    enc.encode(ROOT_KEM_HKDF_INFO),
    32,
  )
  const kemPubBytes = x25519.getPublicKey(kemSeed)

  const userId = await userIdFromEdPub(edPubBytes)

  master.fill(0)

  return {
    userId,
    keys: {
      edPriv: bytesToHex(edSeed),
      edPub: bytesToHex(edPubBytes),
      kemPriv: bytesToHex(kemSeed),
      kemPub: bytesToHex(kemPubBytes),
    },
  }
}

// ── Bootstrap from a secp256k1 root signature ────────────────────────────────

/** Input for {@link deriveRootIdentityFromSecp256k1Signature}. */
export interface Secp256k1BootstrapInput {
  /** Originating secp256k1 x-only pubkey (BIP-340), 64-char lowercase hex. */
  secpPubHex: string
  /**
   * 64-byte BIP-340 Schnorr signature over {@link SECP256K1_BOOTSTRAP_CHALLENGE}
   * produced under `secpPubHex`.
   *
   * **TREAT AS PRIVATE KEY MATERIAL.** This signature is the sole HKDF input
   * that produces the resulting Ed25519 + X25519 seeds. Anyone in possession
   * of the signature can reconstruct the full Starfish identity (just as the
   * passphrase Argon2id master is private). DO NOT log, persist, or transmit
   * it; consume it once and forget it. The library zeroes its own copy after
   * use; the caller is responsible for the lifetime of the buffer they
   * pass in.
   *
   * The caller MUST use a **deterministic BIP-340 signer** (`aux_rand = 0`).
   * BIP-340 permits this. A non-deterministic signer produces a different
   * valid signature on each call → a different identity → permanent loss of
   * access to any caps already issued by the previous derivation. See the
   * function-level docs for the recommended pattern (derive once at install
   * time and cache the resulting identity).
   */
  signature: Uint8Array
}

const SECP_PUBHEX_RE = /^[0-9a-f]{64}$/

/**
 * Derives a v3 root identity from a secp256k1 (Nostr / BIP-340) signature.
 *
 * Lets a user with an existing secp256k1 root (e.g. an nsec) bootstrap a
 * Starfish identity without ever exposing the secp256k1 private key to
 * Starfish: the caller signs a fixed 32-byte challenge with their external
 * signer and hands the signature in. The signature is verified against
 * `secpPubHex`, then its 64 bytes are piped through HKDF-SHA256 to produce the
 * Ed25519 + X25519 seeds. Starfish itself only ever holds the derived Ed25519
 * identity from this point on; the secp256k1 root never appears on the wire.
 *
 * The returned identity carries a `bootstrapOrigin: { kind: "secp256k1", pubHex }`
 * metadata field for external systems to display the origin. It is not signed,
 * not transmitted with caps or requests, and not load-bearing for any check.
 *
 * **The signature is private-key-equivalent.** The Ed25519 + X25519 seeds are
 * derived deterministically from the 64-byte signature alone, so possession of
 * the signature lets anyone reconstruct the full identity. Treat the signature
 * with the same care as the secp256k1 private key itself: never log it,
 * transmit it, or persist it in cleartext. Derive once, then keep only the
 * resulting identity material. See {@link Secp256k1BootstrapInput.signature}.
 *
 * **Determinism contract.** The caller MUST sign with deterministic BIP-340
 * Schnorr (`aux_rand = 0`). BIP-340 permits this. A signer that injects fresh
 * randomness will yield a different signature → different seeds → different
 * `userId` on every call — and any caps previously minted by the earlier
 * derivation become unverifiable against the new root. Recommended pattern:
 * derive **once** at first install, persist the resulting identity (e.g. via
 * `sealWithPassphrase`), and never call this function again for the same
 * secp256k1 root unless you intend to start over.
 */
export async function deriveRootIdentityFromSecp256k1Signature(
  input: Secp256k1BootstrapInput,
): Promise<RootIdentity> {
  const { secpPubHex, signature } = input
  if (typeof secpPubHex !== "string" || !SECP_PUBHEX_RE.test(secpPubHex)) {
    throw new Error("secpPubHex must be 64 lowercase hex characters")
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error("signature must be a 64-byte Uint8Array (BIP-340 Schnorr)")
  }
  // Verify the signature against the originating pubkey. This catches caller
  // bugs and makes `bootstrapOrigin` a verifiable claim — without it, a caller
  // could pass any pubkey alongside a valid signature from a different key, and
  // the recorded origin would mislead external auditors.
  let sigOk = false
  try {
    sigOk = schnorr.verify(signature, SECP256K1_BOOTSTRAP_CHALLENGE, hexToBytes(secpPubHex))
  } catch {
    sigOk = false
  }
  if (!sigOk) {
    throw new Error(
      "BIP-340 Schnorr signature does not verify against secpPubHex over the Starfish bootstrap challenge",
    )
  }

  // HKDF-Extract once over the signature, then Expand twice with distinct infos.
  // `hkdfBytes` runs full Extract+Expand each time; calling it twice with the
  // same IKM/salt re-derives the same PRK internally, then expands per info.
  const enc = new TextEncoder()
  const edSeed = await hkdfBytes(
    signature,
    enc.encode(BOOTSTRAP_SECP_HKDF_SALT),
    enc.encode(BOOTSTRAP_SECP_SIGN_INFO),
    32,
  )
  const kemSeed = await hkdfBytes(
    signature,
    enc.encode(BOOTSTRAP_SECP_HKDF_SALT),
    enc.encode(BOOTSTRAP_SECP_KEM_INFO),
    32,
  )

  const edPubBytes = ed25519.getPublicKey(edSeed)
  const kemPubBytes = x25519.getPublicKey(kemSeed)
  const userId = await userIdFromEdPub(edPubBytes)

  // Best-effort wipe of the signature copy we hold (the caller still owns
  // their original buffer).
  const sigCopy = new Uint8Array(signature)
  sigCopy.fill(0)

  return {
    userId,
    keys: {
      edPriv: bytesToHex(edSeed),
      edPub: bytesToHex(edPubBytes),
      kemPriv: bytesToHex(kemSeed),
      kemPub: bytesToHex(kemPubBytes),
    },
    bootstrapOrigin: { kind: "secp256k1", pubHex: secpPubHex },
  }
}
