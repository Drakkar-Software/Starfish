/** Shared hex→bytes helper for the suite implementations. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

/** Shared bytes→hex helper for the suite implementations (lowercase). */
export function bytesToHex(bytes: Uint8Array): string {
  let s = ""
  for (const b of bytes) s += b.toString(16).padStart(2, "0")
  return s
}

/**
 * Reject an all-zero KEM shared secret. For X25519 this catches the low-order
 * point attack (RFC 7748 §6.1); for secp256k1 a valid point never has an
 * all-zero x-coordinate, so a zero result means a degenerate input slipped
 * through. Either way the wrap key would be predictable — fail closed.
 */
export function assertUsableSharedSecret(secret: Uint8Array): void {
  let acc = 0
  for (const b of secret) acc |= b
  if (acc === 0) throw new Error("Rejected zero KEM shared secret (degenerate point)")
}
