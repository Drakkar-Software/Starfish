/**
 * Platform abstraction for crypto and base64 operations.
 *
 * Browser and Node.js >= 15 work with zero configuration (globalThis.crypto).
 * React Native users must call configurePlatform() before using the SDK.
 *
 * The default Base64 provider uses a **chunked** btoa/atob path instead of the
 * naive `btoa(String.fromCharCode(...data))` spread, which overflows the call-
 * stack on multi-megabyte payloads. All paths (browser/Node/Hermes/pure) process
 * bytes in fixed-size windows so the stack depth is O(1) regardless of blob size.
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
    deriveBits(
      algorithm: HkdfParams,
      baseKey: CryptoKey,
      length: number,
    ): Promise<ArrayBuffer>
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
 * import { configurePlatform } from "@drakkar.software/starfish-client"
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
    "starfish-client: No crypto provider available. " +
      "In React Native, call configurePlatform({ crypto: ... }) before using the SDK.",
  )
}

// Chunk size for base64 operations: a multiple of 3 so every chunk produces a
// valid, padding-free fragment, and small enough to stay under V8's apply limit
// (~65 536 args ≈ 0x8000 bytes).
const _B64_CHUNK = 0x6000 // 24 576 bytes

// ── Pure-JS base64 codec (no btoa/atob dependency) ────────────────────────────
// Used as the default fallback when btoa/atob are absent (React Native / Hermes).

const _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

const _REVERSE = (() => {
  const table = new Int16Array(128).fill(-1)
  for (let i = 0; i < _ALPHABET.length; i++) table[_ALPHABET.charCodeAt(i)] = i
  return table
})()

function _encodePure(data: Uint8Array): string {
  const len = data.length
  const full = len - (len % 3)
  const parts: string[] = []
  for (let start = 0; start < full; start += _B64_CHUNK) {
    const stop = Math.min(start + _B64_CHUNK, full)
    let s = ""
    for (let i = start; i < stop; i += 3) {
      const n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
      s +=
        _ALPHABET[(n >> 18) & 63] +
        _ALPHABET[(n >> 12) & 63] +
        _ALPHABET[(n >> 6) & 63] +
        _ALPHABET[n & 63]
    }
    parts.push(s)
  }
  if (len - full === 1) {
    const n = data[full] << 16
    parts.push(_ALPHABET[(n >> 18) & 63] + _ALPHABET[(n >> 12) & 63] + "==")
  } else if (len - full === 2) {
    const n = (data[full] << 16) | (data[full + 1] << 8)
    parts.push(_ALPHABET[(n >> 18) & 63] + _ALPHABET[(n >> 12) & 63] + _ALPHABET[(n >> 6) & 63] + "=")
  }
  return parts.join("")
}

function _decodePure(encoded: string): Uint8Array {
  let validLen = encoded.length
  while (validLen > 0 && encoded.charCodeAt(validLen - 1) === 61) validLen--
  const out = new Uint8Array((validLen * 3) >> 2)
  let o = 0,
    buf = 0,
    bits = 0
  for (let i = 0; i < validLen; i++) {
    const code = encoded.charCodeAt(i)
    const v = code < 128 ? _REVERSE[code] : -1
    if (v < 0) continue
    buf = (buf << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out[o++] = (buf >> bits) & 0xff
    }
  }
  return o === out.length ? out : out.subarray(0, o)
}

/** Resolve the active base64 provider. */
export function getBase64(): Base64Provider {
  if (_base64) return _base64
  if (typeof globalThis !== "undefined" && typeof globalThis.btoa === "function") {
    return {
      /**
       * Chunked encode — walks bytes in fixed windows instead of spreading the
       * whole array into `String.fromCharCode`. Avoids stack overflow on
       * multi-MB blobs in browser and Hermes.
       */
      encode(data: Uint8Array): string {
        let binary = ""
        for (let i = 0; i < data.length; i += _B64_CHUNK) {
          binary += String.fromCharCode.apply(
            null,
            data.subarray(i, i + _B64_CHUNK) as unknown as number[],
          )
        }
        return btoa(binary)
      },
      decode(encoded: string): Uint8Array {
        const binary = atob(encoded)
        const out = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
        return out
      },
    }
  }
  // Pure-JS fallback — for environments without btoa/atob (React Native /
  // Hermes without a polyfill). No injection needed; hosts can still override
  // via configurePlatform({ base64: ... }) if they have a faster native codec.
  return { encode: _encodePure, decode: _decodePure }
}
