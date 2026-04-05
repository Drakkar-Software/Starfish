/**
 * Platform abstraction for crypto and base64 operations.
 *
 * Browser and Node.js >= 15 work with zero configuration (globalThis.crypto).
 * React Native users must call configurePlatform() before using the SDK.
 */

/** Minimal crypto interface required by the SDK (subset of Web Crypto API). */
export interface CryptoProvider {
  subtle: {
    digest(algorithm: string, data: BufferSource): Promise<ArrayBuffer>
    importKey(
      format: "raw",
      keyData: BufferSource,
      algorithm: string | Algorithm,
      extractable: boolean,
      keyUsages: KeyUsage[],
    ): Promise<CryptoKey>
    deriveKey(
      algorithm: HkdfParams,
      baseKey: CryptoKey,
      derivedKeyType: AesKeyGenParams,
      extractable: boolean,
      keyUsages: KeyUsage[],
    ): Promise<CryptoKey>
    encrypt(
      algorithm: AesGcmParams,
      key: CryptoKey,
      data: BufferSource,
    ): Promise<ArrayBuffer>
    decrypt(
      algorithm: AesGcmParams,
      key: CryptoKey,
      data: BufferSource,
    ): Promise<ArrayBuffer>
  }
  getRandomValues<T extends ArrayBufferView>(array: T): T
}

/** Base64 encode/decode for Uint8Array <-> string. */
export interface Base64Provider {
  encode(data: Uint8Array): string
  decode(encoded: string): Uint8Array
}

export interface PlatformConfig {
  crypto?: CryptoProvider
  base64?: Base64Provider
}

let _crypto: CryptoProvider | undefined
let _base64: Base64Provider | undefined

/**
 * Configure platform-specific providers for environments
 * that lack the Web Crypto API (e.g., React Native).
 *
 * Call once at app startup, before using any SDK functions.
 * Not needed for browser or Node.js >= 15.
 *
 * @example
 * ```ts
 * import { configurePlatform } from "@starfish/client"
 * import QuickCrypto from "react-native-quick-crypto"
 *
 * configurePlatform({
 *   crypto: QuickCrypto,
 *   base64: {
 *     encode: (data) => Buffer.from(data).toString("base64"),
 *     decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
 *   },
 * })
 * ```
 */
export function configurePlatform(config: PlatformConfig): void {
  if (config.crypto) _crypto = config.crypto
  if (config.base64) _base64 = config.base64
}

/** Resolve the active crypto provider. */
export function getCrypto(): CryptoProvider {
  if (_crypto) return _crypto
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto as unknown as CryptoProvider
  }
  throw new Error(
    "@starfish/client: No crypto provider available. " +
      "In React Native, call configurePlatform({ crypto: ... }) before using the SDK.",
  )
}

/** Resolve the active base64 provider. */
export function getBase64(): Base64Provider {
  if (_base64) return _base64
  if (typeof globalThis !== "undefined" && typeof globalThis.btoa === "function") {
    return {
      encode(data: Uint8Array): string {
        return btoa(String.fromCharCode(...data))
      },
      decode(encoded: string): Uint8Array {
        return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0))
      },
    }
  }
  throw new Error(
    "@starfish/client: No base64 provider available. " +
      "In React Native, call configurePlatform({ base64: ... }) before using the SDK.",
  )
}
