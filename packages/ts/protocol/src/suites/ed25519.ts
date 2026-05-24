/**
 * `ed25519` suite — the original Starfish identity model: Ed25519 signing +
 * X25519 KEM (separate keys). The sign/verify halves are a behavior-preserving
 * extraction of the inline `ed25519.sign` / `ed25519.verify` calls that
 * previously lived in `cap.ts`, `request-signing.ts`, and `revocation.ts`; the
 * KEM half is the X25519 ECDH that previously lived inline in the keyring and
 * pairing layers — moved here byte-for-byte so existing wrap vectors are
 * unchanged.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import type { CryptoSuite } from "./types.js"
import { assertUsableSharedSecret, bytesToHex, hexToBytes } from "./_hex.js"

export const ed25519Suite: CryptoSuite = {
  alg: "ed25519",
  sign(message, privHex) {
    return ed25519.sign(message, hexToBytes(privHex))
  },
  verify(sig, message, pubHex) {
    try {
      return ed25519.verify(sig, message, hexToBytes(pubHex))
    } catch {
      return false
    }
  },
  deriveSharedSecret(privHex, peerPubHex) {
    const shared = x25519.getSharedSecret(hexToBytes(privHex), hexToBytes(peerPubHex))
    assertUsableSharedSecret(shared)
    return shared
  },
  generateKemKeypair() {
    const priv = x25519.utils.randomSecretKey()
    return { privHex: bytesToHex(priv), pubHex: bytesToHex(x25519.getPublicKey(priv)) }
  },
  kemPublic(privHex) {
    return bytesToHex(x25519.getPublicKey(hexToBytes(privHex)))
  },
}
