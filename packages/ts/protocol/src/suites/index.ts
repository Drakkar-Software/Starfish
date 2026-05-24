/**
 * Crypto-suite registry. Maps an `alg` tag to its {@link CryptoSuite}.
 *
 * Only *implemented* suites are registered — `getSuite` throws for an
 * unimplemented `alg` rather than silently falling back to a different curve,
 * which would let an attacker pick the weaker/wrong scheme.
 */
import type { Alg, CryptoSuite } from "./types.js"
import { ed25519Suite } from "./ed25519.js"
import { secp256k1SchnorrSuite } from "./secp256k1.js"

/** Default suite for newly created identities when none is specified. */
export const DEFAULT_ALG: Alg = "ed25519"

const REGISTRY: Partial<Record<Alg, CryptoSuite>> = {
  ed25519: ed25519Suite,
  "secp256k1-schnorr": secp256k1SchnorrSuite,
}

/** True when `x` is a recognized `alg` string (implemented or not). */
export function isAlg(x: unknown): x is Alg {
  return x === "ed25519" || x === "secp256k1-schnorr"
}

/**
 * Whether a suite uses a **separate** KEM key (distinct from its signing key).
 * `ed25519` pairs Ed25519 signing with a separate X25519 KEM key, so a cap's
 * `subKem` is required. `secp256k1-schnorr` reuses the one secp256k1 key for
 * both signing and ECDH, so `subKem` is absent (the KEM key derives from `sub`).
 */
export function suiteHasSeparateKem(alg: Alg): boolean {
  return alg === "ed25519"
}

/**
 * Resolve the suite for `alg` (defaulting to {@link DEFAULT_ALG}). Throws if the
 * algorithm is unknown or not yet implemented.
 */
export function getSuite(alg: Alg | undefined = DEFAULT_ALG): CryptoSuite {
  const suite = REGISTRY[alg]
  if (!suite) throw new Error(`crypto suite not available: ${String(alg)}`)
  return suite
}

export type { Alg, CryptoSuite } from "./types.js"
