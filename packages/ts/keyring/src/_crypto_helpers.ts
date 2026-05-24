/**
 * Internal crypto helpers shared by identity, keyring, and pairing.
 *
 * The leading underscore prefix marks these as low-level building blocks. They
 * are generic encoding/KDF utilities (hex conversion, byte concat, HKDF) — not
 * key material — and `index.ts` re-exports them for the identities/pairing
 * packages that build on the same primitives.
 *
 * These helpers were previously duplicated verbatim across three modules
 * (`identity.ts`, `keyring.ts`, `pairing.ts`); consolidating them keeps the
 * byte-level behavior identical while removing copy-paste drift risk.
 */

import { getCrypto } from "@drakkar.software/starfish-protocol"

/**
 * HKDF-SHA256 → raw bytes. Shared by identity, keyring, pairing.
 *
 * Web Crypto's `deriveBits` is widened from `CryptoProvider` (which only
 * models digest / importKey / deriveKey / encrypt / decrypt) via a local
 * cast — every supported backend (Web Crypto, Node.js, react-native-quick-
 * crypto) implements `deriveBits`, so we widen the type here rather than
 * expanding the SDK contract.
 *
 * Mirrors the Python `HKDF(...).derive(ikm)` API exactly — the protocol
 * package's `deriveKey` UTF-8-encodes its input, which does not match the
 * cross-language test vectors that gate these helpers.
 */
export async function hkdfBytes(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lengthBytes: number = 32,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle as unknown as SubtleCrypto
  const keyMaterial = await subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"])
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    keyMaterial,
    lengthBytes * 8,
  )
  return new Uint8Array(bits)
}

/** Lowercase-hex encoding of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

/** Decode a lowercase- or uppercase-hex string into bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Concatenate any number of byte arrays into a single fresh `Uint8Array`. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.byteLength, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.byteLength
  }
  return out
}
