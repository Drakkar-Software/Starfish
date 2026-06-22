/**
 * kemSig — Ed25519 signature of a KEM public key.
 *
 * When an identity shares its KEM public key (e.g., in a join-request or
 * profile), the receiver must verify that the sender actually owns that KEM
 * key — otherwise a MITM could substitute their own KEM key and intercept
 * sealed messages. The kemSig is produced by signing the raw KEM-pub bytes
 * with the sender's Ed25519 private key; the verifier checks the signature
 * against the sender's known Ed25519 public key.
 */
import { ed25519 } from "@noble/curves/ed25519.js"
import { hexToBytes, bytesToHex } from "@drakkar.software/starfish-keyring"

/**
 * Sign `kemPub` with `edPriv`, returning the signature as lowercase hex.
 */
export function signKemSig(keys: { kemPub: string; edPriv: string }): string {
  const msg = hexToBytes(keys.kemPub)
  const priv = hexToBytes(keys.edPriv)
  return bytesToHex(ed25519.sign(msg, priv))
}

/**
 * Verify that `kemSig` is a valid Ed25519 signature of `kemPub` by `edPub`.
 * Returns `false` (does NOT throw) when `kemSig` is absent or malformed.
 */
export function verifyKemSig(
  edPub: string,
  kemPub: string,
  kemSig: string | undefined,
): boolean {
  if (!kemSig) return false
  try {
    return ed25519.verify(hexToBytes(kemSig), hexToBytes(kemPub), hexToBytes(edPub))
  } catch {
    return false
  }
}
