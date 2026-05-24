import { getCrypto } from "./platform.js"

const ALGO = "AES-GCM"
export const IV_BYTES = 12
export const ENCRYPTED_KEY = "_encrypted"

/**
 * Encrypt/decrypt contract for client-side E2E encryption.
 *
 * Lives in the shared protocol layer so the client (`SyncManager`, which
 * consumes an `Encryptor` via its `encryptor` option) and the encryptor
 * implementations (e.g. the keyring's `createKeyringEncryptor`) can both
 * reference the contract without a workspace dependency cycle.
 */
export interface Encryptor {
  encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>>
  decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>>
}

/**
 * Derive the raw 32-byte AES-256 key via HKDF-SHA256 over UTF-8(`secret`) with
 * UTF-8(`salt`) / UTF-8(`info`).
 *
 * Exposed for cross-language conformance testing — the shared `crypto.json`
 * vector anchors these exact bytes, and the Python `derive_key` must produce
 * the same. Production code should use {@link deriveKey}, which imports these
 * bytes as a non-extractable AES-GCM key.
 */
export async function deriveAesKeyBytes(
  secret: string,
  salt: string,
  info: string,
): Promise<Uint8Array> {
  const enc = new TextEncoder()
  const c = getCrypto()
  const keyMaterial = await c.subtle.importKey(
    "raw",
    enc.encode(secret),
    "HKDF",
    false,
    ["deriveBits"],
  )
  const bits = await c.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: enc.encode(salt),
      info: enc.encode(info),
    },
    keyMaterial,
    256,
  )
  return new Uint8Array(bits)
}

export async function deriveKey(secret: string, salt: string, info: string): Promise<CryptoKey> {
  const keyBytes = await deriveAesKeyBytes(secret, salt, info)
  return getCrypto().subtle.importKey(
    "raw",
    keyBytes as BufferSource,
    { name: ALGO },
    false,
    ["encrypt", "decrypt"],
  )
}
