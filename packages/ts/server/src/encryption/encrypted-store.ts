import { deriveKey, IV_BYTES, getCrypto, getBase64 } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import { HKDF_INFO_DEFAULT } from "../constants.js"

export class EncryptedObjectStore implements ObjectStore {
  private _inner: ObjectStore
  private _keyPromise: Promise<CryptoKey>

  constructor(
    inner: ObjectStore,
    secret: string,
    salt: string,
    info: string = HKDF_INFO_DEFAULT,
  ) {
    this._inner = inner
    this._keyPromise = deriveKey(secret, salt, info)
  }

  private async _encrypt(plaintext: string): Promise<string> {
    const key = await this._keyPromise
    const c = getCrypto()
    const b64 = getBase64()
    const iv = new Uint8Array(IV_BYTES)
    c.getRandomValues(iv)
    const data = new TextEncoder().encode(plaintext)
    const ciphertext = new Uint8Array(
      await c.subtle.encrypt({ name: "AES-GCM", iv }, key, data),
    )
    const combined = new Uint8Array(iv.length + ciphertext.length)
    combined.set(iv)
    combined.set(ciphertext, iv.length)
    return b64.encode(combined)
  }

  private async _decrypt(encoded: string): Promise<string> {
    const key = await this._keyPromise
    const c = getCrypto()
    const b64 = getBase64()
    const combined = b64.decode(encoded)
    if (combined.length < IV_BYTES) {
      throw new Error("Encrypted data is too short")
    }
    const iv = combined.slice(0, IV_BYTES)
    const ciphertext = combined.slice(IV_BYTES)
    try {
      const plaintext = await c.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext)
      return new TextDecoder().decode(plaintext)
    } catch {
      throw new Error("Decryption failed: data may be tampered or key is incorrect")
    }
  }

  async getString(key: string, context?: StoreContext): Promise<string | null> {
    const raw = await this._inner.getString(key, context)
    if (raw == null) return null
    return this._decrypt(raw)
  }

  async put(
    key: string,
    body: string,
    opts?: { contentType?: string; cacheControl?: string },
    context?: StoreContext,
  ): Promise<void> {
    const encrypted = await this._encrypt(body)
    await this._inner.put(key, encrypted, opts, context)
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    context?: StoreContext,
  ): Promise<string[]> {
    return this._inner.listKeys(prefix, opts, context)
  }

  async delete(key: string, context?: StoreContext): Promise<void> {
    return this._inner.delete(key, context)
  }

  async deleteMany(keys: string[], context?: StoreContext): Promise<void> {
    return this._inner.deleteMany(keys, context)
  }
}
