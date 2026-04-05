import { deriveKey, getCrypto, getBase64, IV_BYTES } from "@starfish/protocol"
import { AbstractObjectStore } from "../storage/base.js"
import { HKDF_INFO_DEFAULT } from "../constants.js"

const ALGO = "AES-GCM"

export class EncryptedObjectStore extends AbstractObjectStore {
  private readonly inner: AbstractObjectStore
  private readonly keyPromise: Promise<CryptoKey>

  constructor(
    inner: AbstractObjectStore,
    secret: string,
    salt: string,
    info = HKDF_INFO_DEFAULT,
  ) {
    super()
    this.inner = inner
    this.keyPromise = deriveKey(secret, salt, info)
  }

  private async encrypt(plaintext: string): Promise<string> {
    const key = await this.keyPromise
    const c = getCrypto()
    const b64 = getBase64()
    const data = new TextEncoder().encode(plaintext)
    const iv = c.getRandomValues(new Uint8Array(IV_BYTES))
    const ciphertext = await c.subtle.encrypt({ name: ALGO, iv }, key, data)
    const combined = new Uint8Array(iv.length + ciphertext.byteLength)
    combined.set(iv)
    combined.set(new Uint8Array(ciphertext), iv.length)
    return b64.encode(combined)
  }

  private async decrypt(encoded: string): Promise<string> {
    const key = await this.keyPromise
    const c = getCrypto()
    const b64 = getBase64()
    const combined = b64.decode(encoded)
    if (combined.length < IV_BYTES) {
      throw new Error("Encrypted data is too short")
    }
    const iv = combined.slice(0, IV_BYTES)
    const ciphertext = combined.slice(IV_BYTES)
    const plaintext = await c.subtle.decrypt({ name: ALGO, iv }, key, ciphertext)
    return new TextDecoder().decode(plaintext)
  }

  async getString(key: string): Promise<string | null> {
    const raw = await this.inner.getString(key)
    if (raw === null) return null
    return this.decrypt(raw)
  }

  async put(
    key: string,
    body: string,
    options?: { contentType?: string; cacheControl?: string },
  ): Promise<void> {
    const encrypted = await this.encrypt(body)
    return this.inner.put(key, encrypted, options)
  }

  async listKeys(
    prefix: string,
    options?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    return this.inner.listKeys(prefix, options)
  }

  async delete(key: string): Promise<void> {
    return this.inner.delete(key)
  }

  async deleteMany(keys: string[]): Promise<void> {
    return this.inner.deleteMany(keys)
  }
}
