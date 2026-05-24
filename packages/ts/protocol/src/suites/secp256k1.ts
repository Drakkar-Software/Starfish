/**
 * `secp256k1-schnorr` suite — the "Nostr" identity model: BIP-340 Schnorr
 * signing + secp256k1 ECDH (the KEM half), over one secp256k1 key.
 *
 * Compatibility note: this shares Nostr's *key type* (secp256k1 x-only) and the
 * ECDH *primitive*, but is NOT Nostr/NIP-44 wire-interoperable. Signatures are
 * over `sha256(canonical Starfish bytes)`, not a NIP-01 event id, and the
 * keyring wrap uses Starfish's own HKDF (`salt="starfish-wrap"`, suite-tagged
 * info) — not NIP-44's `conversation_key` / per-message nonce. A stock Nostr
 * client can neither verify these signatures nor unwrap these keys.
 *
 * Three deliberate choices keep this byte-identical and reproducible across the
 * TypeScript (`@noble/curves`) and Python (`coincurve`) implementations:
 *
 * 1. **Hash-then-sign.** BIP-340 places the message directly into the challenge
 *    `e = tagged_hash("BIP0340/challenge", R || P || m)`. `@noble` accepts an
 *    arbitrary-length `m`, but libsecp256k1's `schnorrsig_sign32` (what
 *    `coincurve` wraps) takes exactly 32 bytes. So both sides sign
 *    `sha256(message)` — a 32-byte digest — and agree.
 * 2. **Deterministic `aux_rand = 0`.** BIP-340 §3 permits a zero auxiliary
 *    randomness, yielding a deterministic signature (like Ed25519). This makes
 *    cross-language test vectors reproducible. It forgoes the extra
 *    side-channel hardening random aux would add — an accepted trade for
 *    determinism, matching the `ed25519` suite's behavior.
 * 3. **ECDH = x-coordinate of the shared point, x-only keys lifted even-y.**
 *    Public keys are 32-byte BIP-340 x-only (no parity). For ECDH we lift the
 *    peer to its even-y point (`0x02‖x`), multiply by our scalar, and take the
 *    **x-coordinate** of the result. This is parity-free — `k·P` and `k·(−P)`
 *    share an x — so it is symmetric without storing parity. This is the same
 *    ECDH *primitive* shape Nostr/NIP-44 uses; the wrap KDF on top differs (see
 *    the compatibility note above). Byte-identical to `coincurve`'s
 *    `PublicKey(b"\x02"+x).multiply(priv)` x.
 *
 * Keys are 32-byte secp256k1 x-only public keys / scalars, lowercase hex.
 */
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js"
import { sha256 } from "@noble/hashes/sha2.js"
import type { CryptoSuite } from "./types.js"
import { assertUsableSharedSecret, bytesToHex, hexToBytes } from "./_hex.js"

/** Deterministic auxiliary randomness — 32 zero bytes (BIP-340 permits this). */
const ZERO_AUX = new Uint8Array(32)

/** Lift an x-only key to its even-y compressed point (`0x02‖x`) for ECDH. */
function liftEvenY(xOnly: Uint8Array): Uint8Array {
  const out = new Uint8Array(33)
  out[0] = 0x02
  out.set(xOnly, 1)
  return out
}

export const secp256k1SchnorrSuite: CryptoSuite = {
  alg: "secp256k1-schnorr",
  sign(message, privHex) {
    return schnorr.sign(sha256(message), hexToBytes(privHex), ZERO_AUX)
  },
  verify(sig, message, pubHex) {
    try {
      return schnorr.verify(sig, sha256(message), hexToBytes(pubHex))
    } catch {
      return false
    }
  },
  deriveSharedSecret(privHex, peerPubHex) {
    // getSharedSecret returns the compressed shared point (prefix ‖ x); take x.
    const point = secp256k1.getSharedSecret(hexToBytes(privHex), liftEvenY(hexToBytes(peerPubHex)), true)
    const sharedX = point.slice(1, 33)
    assertUsableSharedSecret(sharedX)
    return sharedX
  },
  generateKemKeypair() {
    const priv = secp256k1.utils.randomSecretKey()
    return { privHex: bytesToHex(priv), pubHex: bytesToHex(schnorr.getPublicKey(priv)) }
  },
  kemPublic(privHex) {
    return bytesToHex(schnorr.getPublicKey(hexToBytes(privHex)))
  },
}
