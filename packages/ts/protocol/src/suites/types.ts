/**
 * Crypto-suite contract — the seam that lets one Starfish deployment carry
 * multiple identity models side by side, selectable per user.
 *
 * A *suite* bundles the signature scheme (and, in later phases, the KEM and
 * key encoding) behind one `alg` tag. The tag travels inside every signed
 * canonical input (cap-certs, request signatures, revocation lists), so the
 * algorithm an attacker would have to forge against is itself authenticated —
 * stripping or downgrading `alg` changes the signed bytes and fails
 * verification.
 *
 * Two suites are shipped:
 * - `ed25519`          — Ed25519 signing + X25519 KEM (the original model).
 * - `secp256k1-schnorr` — BIP-340 Schnorr signing + secp256k1 ECDH ("nostr").
 */

/** Algorithm identifier carried by every signed artifact. */
export type Alg = "ed25519" | "secp256k1-schnorr"

/**
 * Signature + KEM operations for one suite. Keys are passed as lowercase hex;
 * the suite owns the hex↔bytes conversion and any curve-specific encoding (e.g.
 * x-only pubkeys for Schnorr). `verify` must never throw — it returns `false`
 * on any decode/curve error so callers fail closed.
 *
 * The KEM half operates on the suite's **KEM** keys, which may differ from its
 * signing keys: `ed25519` pairs Ed25519 signing with a *separate* X25519 KEM
 * key, while `secp256k1-schnorr` reuses its one secp256k1 key for both. So the
 * `deriveSharedSecret`/`kemPublic`/`generateKemKeypair` keys are X25519 for the
 * `ed25519` suite and secp256k1 x-only for `secp256k1-schnorr`.
 */
export interface CryptoSuite {
  readonly alg: Alg
  /** Sign `message` with the issuer/device private key (hex). */
  sign(message: Uint8Array, privHex: string): Uint8Array
  /** Verify `sig` over `message` against `pubHex`. Returns false, never throws. */
  verify(sig: Uint8Array, message: Uint8Array, pubHex: string): boolean
  /**
   * KEM: derive a 32-byte shared secret from our KEM private key and a peer's
   * KEM public key (both hex, this suite's KEM key type). Throws on an invalid
   * peer point or a degenerate (all-zero) result so callers fail closed.
   */
  deriveSharedSecret(privHex: string, peerPubHex: string): Uint8Array
  /** Generate a fresh ephemeral KEM keypair for this suite (hex). */
  generateKemKeypair(): { privHex: string; pubHex: string }
  /** Derive the KEM public key (hex) from a KEM private key (hex). */
  kemPublic(privHex: string): string
}
