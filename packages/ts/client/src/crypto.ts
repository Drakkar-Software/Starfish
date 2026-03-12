import { getCrypto, getBase64, IV_BYTES, ENCRYPTED_KEY, deriveKey } from "@starfish/protocol"

const ALGO = "AES-GCM"

export { ENCRYPTED_KEY }

/** Encrypt/decrypt interface for client-side E2E encryption. */
export interface Encryptor {
  encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>>
  decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>>
}

/**
 * Creates an Encryptor that uses AES-256-GCM with HKDF-derived keys.
 */
export function createEncryptor(secret: string, salt: string, info: string = "starfish-e2e"): Encryptor {
  if (!secret) throw new Error("encryptionSecret must not be empty")
  if (!salt) throw new Error("encryptionSalt must not be empty")
  const keyPromise = deriveKey(secret, salt, info)

  return {
    async encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>> {
      const key = await keyPromise
      const c = getCrypto()
      const b64 = getBase64()
      const plaintext = new TextEncoder().encode(JSON.stringify(data))
      const iv = c.getRandomValues(new Uint8Array(IV_BYTES))
      const ciphertext = await c.subtle.encrypt({ name: ALGO, iv }, key, plaintext)

      const combined = new Uint8Array(iv.length + ciphertext.byteLength)
      combined.set(iv)
      combined.set(new Uint8Array(ciphertext), iv.length)

      return { [ENCRYPTED_KEY]: b64.encode(combined) }
    },

    async decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>> {
      const encoded = wrapper[ENCRYPTED_KEY]
      if (typeof encoded !== "string") {
        throw new Error("Expected encrypted data but received unencrypted document")
      }

      const key = await keyPromise
      const c = getCrypto()
      const b64 = getBase64()
      const combined = b64.decode(encoded)
      if (combined.length < IV_BYTES) {
        throw new Error("Encrypted data is too short")
      }
      const iv = combined.slice(0, IV_BYTES)
      const ciphertext = combined.slice(IV_BYTES)
      try {
        const plaintext = await c.subtle.decrypt({ name: ALGO, iv }, key, ciphertext)
        return JSON.parse(new TextDecoder().decode(plaintext))
      } catch (err) {
        throw new Error("Decryption failed: data may be tampered or key is incorrect", { cause: err })
      }
    },
  }
}
