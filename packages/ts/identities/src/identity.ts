import { getCrypto } from "@drakkar.software/starfish-protocol"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { argon2id } from "hash-wasm"

import { bytesToHex, hkdfBytes } from "@drakkar.software/starfish-keyring"

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
 * A v3 root identity bound to a passphrase: the deterministic Ed25519 + X25519
 * key pairs and the short `userId` derived from the Ed25519 public key.
 */
export interface RootIdentity {
  /** First 32 hex chars (16 bytes) of `sha256(rootEdPub)`. */
  userId: string
  /** Root Ed25519 (signing) and X25519 (KEM) key pairs as hex. */
  keys: RootKeyPair
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

/**
 * Derives a v3 root identity from a passphrase.
 *
 * Pipeline: Argon2id (memory-hard password stretch) → HKDF-SHA256 (expand into
 * Ed25519 + X25519 seeds) → public key derivation → userId. The Ed25519 public
 * key is hashed (SHA-256) and the first 32 hex characters become the `userId`.
 *
 * This is the v3 identity primitive — it does not create cap-certs or device
 * keys. Those are produced by higher-level operations (pairing, bootstrap).
 *
 * @param passphrase The user's passphrase. Must be non-empty.
 */
export async function deriveRootIdentity(passphrase: string): Promise<RootIdentity> {
  if (!passphrase.trim()) throw new Error("Passphrase must not be empty")

  // Stage 1 — Argon2id stretches the passphrase into a 32-byte master secret.
  const master = await argon2idStretch(passphrase)

  // Stage 2 — HKDF-SHA256 expands the master into domain-separated subkeys.
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

  // userId = first 32 hex chars of SHA-256(rootEdPub bytes)
  const c = getCrypto()
  const pubHash = await c.subtle.digest("SHA-256", edPubBytes as BufferSource)
  const userId = bytesToHex(new Uint8Array(pubHash)).slice(0, 32)

  // Best-effort: zero the master seed once subkeys are derived. The runtime
  // does not guarantee no copies were made by GC, but this prevents the
  // master from lingering in our scope after we're done with it.
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
