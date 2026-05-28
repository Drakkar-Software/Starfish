/** Shared hex→bytes helper. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  // Reject non-hex characters: `parseInt` returns NaN for them, which coerces
  // to 0 in a Uint8Array — silently turning malformed input into zero bytes
  // (and diverging from Python's `bytes.fromhex`, which raises). Fail closed.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hex string has invalid characters")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

/** Shared bytes→hex helper (lowercase). */
export function bytesToHex(bytes: Uint8Array): string {
  let s = ""
  for (const b of bytes) s += b.toString(16).padStart(2, "0")
  return s
}

/**
 * Reject an all-zero X25519 shared secret — the low-order point attack
 * (RFC 7748 §6.1). The wrap key derived from it would be predictable — fail
 * closed.
 */
export function assertUsableSharedSecret(secret: Uint8Array): void {
  let acc = 0
  for (const b of secret) acc |= b
  if (acc === 0) throw new Error("Rejected zero KEM shared secret (degenerate point)")
}
