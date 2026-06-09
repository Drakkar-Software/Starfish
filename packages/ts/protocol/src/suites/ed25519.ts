/**
 * ed25519 primitives — the single signature + KEM suite Starfish speaks on the
 * wire. Ed25519 for signing; X25519 for the KEM half (the two are separate
 * keys, hence `kemPublic` and `generateKemKeypair` operate on X25519).
 *
 * Callers pass keys as lowercase hex; this module owns the hex↔bytes conversion.
 * `verify` never throws — it returns `false` on any decode/curve error so callers
 * fail closed.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { assertUsableSharedSecret, bytesToHex, hexToBytes } from "./_hex.js"

/** Sign `message` with the signer's Ed25519 private key (hex). */
export function sign(message: Uint8Array, privHex: string): Uint8Array {
  return ed25519.sign(message, hexToBytes(privHex))
}

/** Verify `sig` over `message` against `pubHex`. Returns false, never throws. */
export function verify(sig: Uint8Array, message: Uint8Array, pubHex: string): boolean {
  try {
    return ed25519.verify(sig, message, hexToBytes(pubHex))
  } catch {
    return false
  }
}

/**
 * X25519 ECDH: derive a 32-byte shared secret from our KEM private key and a
 * peer's KEM public key (both hex). Throws on an invalid peer point or a
 * degenerate (all-zero) result so callers fail closed.
 */
export function deriveSharedSecret(privHex: string, peerPubHex: string): Uint8Array {
  const shared = x25519.getSharedSecret(hexToBytes(privHex), hexToBytes(peerPubHex))
  assertUsableSharedSecret(shared)
  return shared
}

/** Generate a fresh ephemeral X25519 keypair (hex). */
export function generateKemKeypair(): { privHex: string; pubHex: string } {
  const priv = x25519.utils.randomSecretKey()
  return { privHex: bytesToHex(priv), pubHex: bytesToHex(x25519.getPublicKey(priv)) }
}

/** Generate a fresh Ed25519 signing keypair (hex) — the signing counterpart to
 *  {@link generateKemKeypair}. Useful for minting a long-lived author/sealer
 *  identity (e.g. a webhook bot) that is not derived from a passphrase. */
export function generateSignerKeypair(): { privHex: string; pubHex: string } {
  const priv = ed25519.utils.randomSecretKey()
  return { privHex: bytesToHex(priv), pubHex: bytesToHex(ed25519.getPublicKey(priv)) }
}

/** Derive the X25519 public key (hex) from a private key (hex). */
export function kemPublic(privHex: string): string {
  return bytesToHex(x25519.getPublicKey(hexToBytes(privHex)))
}
