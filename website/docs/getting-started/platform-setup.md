---
sidebar_position: 3
---

# Platform Setup

Starfish uses the Web Crypto API for encryption and hashing. Most environments support this natively, but some require configuration.

> **Prerequisites:** [Getting Started](/getting-started/intro)

## Platform Compatibility

| Platform | Setup Required? | Notes |
|----------|----------------|-------|
| Browser (modern) | No | Web Crypto API available natively |
| Node.js >= 15 | No | `crypto.subtle` available globally |
| React Native | Yes | Needs `configurePlatform()` |
| Cloudflare Workers | No | Web Crypto API available |
| Deno | No | Web Crypto API available |

## React Native Setup

React Native doesn't provide `crypto.subtle` or standard base64 utilities. Use `configurePlatform()` to provide them:

```ts
import { configurePlatform } from "@drakkar.software/starfish-client"
import QuickCrypto from "react-native-quick-crypto"
import { encode, decode } from "base-64"

configurePlatform({
  crypto: {
    subtle: QuickCrypto.subtle,
    getRandomValues: (arr) => QuickCrypto.getRandomValues(arr),
  },
  base64: {
    encode: (bytes: Uint8Array) =>
      encode(String.fromCharCode(...bytes)),
    decode: (str: string) =>
      Uint8Array.from(decode(str), (c) => c.charCodeAt(0)),
  },
})
```

Call `configurePlatform()` **once at app startup**, before creating any `SyncManager` or `Encryptor` instances.

### `PlatformConfig`

```ts
interface PlatformConfig {
  crypto?: CryptoProvider
  base64?: Base64Provider
}
```

### `CryptoProvider`

A subset of the Web Crypto API:

```ts
interface CryptoProvider {
  subtle: {
    digest(algorithm: string, data: ArrayBuffer): Promise<ArrayBuffer>
    importKey(
      format: string,
      keyData: ArrayBuffer,
      algorithm: string | object,
      extractable: boolean,
      keyUsages: string[],
    ): Promise<CryptoKey>
    deriveKey(
      algorithm: object,
      baseKey: CryptoKey,
      derivedKeyAlgorithm: object,
      extractable: boolean,
      keyUsages: string[],
    ): Promise<CryptoKey>
    encrypt(algorithm: object, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>
    decrypt(algorithm: object, key: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer>
  }
  getRandomValues(array: Uint8Array): Uint8Array
}
```

### `Base64Provider`

```ts
interface Base64Provider {
  encode(bytes: Uint8Array): string
  decode(str: string): Uint8Array
}
```

## Custom Fetch

For environments without a global `fetch`, or to add interceptors:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  fetch: myCustomFetch,
})
```

Use cases:
- React Native with a polyfilled fetch
- Adding request/response logging
- Injecting custom headers or retry logic at the transport level

## Alternative: Global Polyfill

Instead of `configurePlatform()`, you can polyfill `globalThis.crypto` directly:

```ts
import QuickCrypto from "react-native-quick-crypto"
globalThis.crypto = QuickCrypto as unknown as Crypto
```

If `globalThis.crypto.subtle` and `globalThis.btoa`/`globalThis.atob` are available, Starfish will use them without `configurePlatform()`.

## Next Steps

- [Getting Started](/getting-started/intro) — first sync after platform setup
- [Encryption](/encryption-identity/encryption) — encryption relies on the crypto provider
