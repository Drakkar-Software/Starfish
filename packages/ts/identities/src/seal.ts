/**
 * Passphrase-sealed envelopes — Argon2id (memory-hard stretch) → AES-256-GCM.
 *
 * A small, generic primitive for transporting a secret blob (e.g. a one-way
 * device setup code, which carries private keys) under a user-chosen
 * PIN/passphrase. The sealed envelope is JSON-serialisable and useless on its
 * own: opening it requires the passphrase, which should travel a DIFFERENT
 * channel than the envelope (the out-of-band / two-channel pattern).
 *
 * Construction:
 *   key = Argon2id(NFC(passphrase), randomSalt, ARGON2_PARAMS)   ← per-seal salt
 *   ct  = AES-256-GCM(key, randomIv, plaintext)                  ← tag appended
 *
 * Security notes:
 *  - Strength is bounded by passphrase entropy. Argon2id raises the per-guess
 *    cost but cannot rescue a low-entropy PIN: a 4-digit numeric PIN is still
 *    brute-forceable offline once the envelope is captured. Prefer a real
 *    passphrase when the envelope may be intercepted.
 *  - The KDF header (salt + params) is *implicitly* authenticated: tampering
 *    with it yields a different key (or a malformed nonce), so the GCM tag check
 *    fails on open. `v` and `enc` are NOT in the KDF input, so they are guarded
 *    only by the explicit allow-list in {@link openWithPassphrase}.
 *  - {@link openWithPassphrase} validates the envelope BEFORE running Argon2id,
 *    so a hostile envelope cannot force a multi-GiB memory-hard computation
 *    (denial of service) on the recipient the moment it is pasted.
 */

import { getBase64, getCrypto } from "@drakkar.software/starfish-protocol"
import { argon2id } from "hash-wasm"

import { ARGON2_PARAMS } from "./identity.js"

const SALT_BYTES = 16
const IV_BYTES = 12

/**
 * A passphrase-sealed payload. JSON-serialisable; all byte fields are standard
 * (padded) base64. `v`/`enc` discriminate the format; `kdf` records the
 * Argon2id parameters and per-seal salt; `ct` is the AES-256-GCM ciphertext
 * with the 16-byte tag appended (Web Crypto / AESGCM convention).
 */
export interface SealedEnvelope {
  v: 1
  enc: "passphrase"
  kdf: { alg: "argon2id"; memKiB: number; iter: number; par: number; salt: string }
  iv: string
  ct: string
}

/** Deterministic overrides for {@link sealWithPassphrase} (test vectors only). */
export interface SealOpts {
  /** Override the random 16-byte salt. */
  salt?: Uint8Array
  /** Override the random 12-byte IV. */
  iv?: Uint8Array
}

// One generic failure for every open-side rejection (wrong passphrase, tamper,
// or bad params). Distinguishing them would leak whether the structure was
// valid; callers should surface a single "wrong PIN or corrupted code" message.
const OPEN_FAILED = "Failed to open sealed envelope: wrong passphrase or corrupted/invalid envelope"

async function deriveSealKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  const result = await argon2id({
    password: passphrase.normalize("NFC"),
    salt,
    parallelism: ARGON2_PARAMS.parallelism,
    iterations: ARGON2_PARAMS.iterations,
    memorySize: ARGON2_PARAMS.memoryKiB,
    hashLength: ARGON2_PARAMS.hashLength,
    outputType: "binary",
  })
  return new Uint8Array(result)
}

async function importAesKey(rawKeyBytes: Uint8Array): Promise<CryptoKey> {
  return getCrypto().subtle.importKey(
    "raw",
    rawKeyBytes as BufferSource,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  )
}

/**
 * Seal `plaintext` under `passphrase`. Returns a JSON-serialisable envelope.
 *
 * The passphrase is NFC-normalised before stretching so the same human input
 * produces the same key across platforms. Throws on an empty passphrase.
 */
export async function sealWithPassphrase(
  passphrase: string,
  plaintext: Uint8Array,
  opts: SealOpts = {},
): Promise<SealedEnvelope> {
  if (!passphrase) throw new Error("Passphrase must not be empty")
  const c = getCrypto()
  const salt = opts.salt ?? c.getRandomValues(new Uint8Array(SALT_BYTES))
  const iv = opts.iv ?? c.getRandomValues(new Uint8Array(IV_BYTES))
  const key = await importAesKey(await deriveSealKey(passphrase, salt))
  const ctBuf = await c.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, plaintext as BufferSource)
  const b64 = getBase64()
  return {
    v: 1,
    enc: "passphrase",
    kdf: {
      alg: "argon2id",
      memKiB: ARGON2_PARAMS.memoryKiB,
      iter: ARGON2_PARAMS.iterations,
      par: ARGON2_PARAMS.parallelism,
      salt: b64.encode(salt),
    },
    iv: b64.encode(iv),
    ct: b64.encode(new Uint8Array(ctBuf)),
  }
}

/**
 * Structural type guard: does `value` look like a {@link SealedEnvelope}? Useful
 * to branch between a sealed code and a plaintext blob without throwing.
 */
export function isSealedEnvelope(value: unknown): value is SealedEnvelope {
  if (typeof value !== "object" || value === null) return false
  const v = value as Record<string, unknown>
  if (v.v !== 1 || v.enc !== "passphrase" || typeof v.iv !== "string" || typeof v.ct !== "string") {
    return false
  }
  const kdf = v.kdf
  if (typeof kdf !== "object" || kdf === null) return false
  const k = kdf as Record<string, unknown>
  return k.alg === "argon2id" && typeof k.salt === "string"
}

/**
 * Open an envelope sealed by {@link sealWithPassphrase}. Returns the plaintext.
 *
 * Validates the envelope shape and Argon2id parameters BEFORE doing any KDF
 * work, so a hostile envelope cannot trigger an expensive memory-hard
 * computation. Every failure — malformed envelope, disallowed params, wrong
 * passphrase, or tampered ciphertext — throws the same generic error.
 */
export async function openWithPassphrase(passphrase: string, envelope: SealedEnvelope): Promise<Uint8Array> {
  try {
    if (!isSealedEnvelope(envelope)) throw new Error("malformed envelope")
    const { kdf } = envelope
    // Param allow-list — reject before KDF. Strictest sensible choice: the
    // canonical params. Loosen only if the format ever legitimately varies them.
    if (
      kdf.alg !== "argon2id" ||
      kdf.memKiB !== ARGON2_PARAMS.memoryKiB ||
      kdf.iter !== ARGON2_PARAMS.iterations ||
      kdf.par !== ARGON2_PARAMS.parallelism
    ) {
      throw new Error("disallowed KDF parameters")
    }
    const b64 = getBase64()
    const salt = b64.decode(kdf.salt)
    const iv = b64.decode(envelope.iv)
    const ct = b64.decode(envelope.ct)
    if (salt.length !== SALT_BYTES) throw new Error("bad salt length")
    if (iv.length !== IV_BYTES) throw new Error("bad iv length")
    const key = await importAesKey(await deriveSealKey(passphrase, salt))
    const ptBuf = await getCrypto().subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, ct as BufferSource)
    return new Uint8Array(ptBuf)
  } catch (err) {
    throw new Error(OPEN_FAILED, { cause: err })
  }
}
