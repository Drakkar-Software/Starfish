# KV-backed Pull Cache

`createKvPullCache` implements the `PullCache` interface using any async key-value
store. Use it to persist ciphertext-at-rest in environments that lack IndexedDB
(React Native, Electron, Node.js workers) or to share a cache across browser tabs.

## Interface

```ts
import { createKvPullCache } from "@drakkar.software/starfish-client"
import type { KvStore, KvPullCacheOptions } from "@drakkar.software/starfish-client"

interface KvStore {
  get(key: string): Promise<string | null | undefined>
  set(key: string, value: string): Promise<void>
}

interface KvPullCacheOptions {
  /** Key prefix prepended to every cache key. Default "". */
  prefix?: string
  /** Maximum age in ms before an entry is considered expired. Default: no expiry. */
  maxAgeMs?: number
}
```

## Usage

```ts
import { StarfishClient, createKvPullCache } from "@drakkar.software/starfish-client"
import { MMKV } from "react-native-mmkv"

// Wrap MMKV (React Native) as a KvStore
const mmkv = new MMKV()
const kv: KvStore = {
  get: async (key) => mmkv.getString(key) ?? null,
  set: async (key, value) => mmkv.set(key, value),
}

const client = new StarfishClient({
  baseUrl: "https://api.example.com",
  cache: createKvPullCache(kv, {
    prefix: "starfish.",
    maxAgeMs: 5 * 60 * 1000, // 5 minutes
  }),
})
```

## Adapters for common stores

### `AsyncStorage` (React Native)

```ts
import AsyncStorage from "@react-native-async-storage/async-storage"

const cache = createKvPullCache({
  get: AsyncStorage.getItem,
  set: AsyncStorage.setItem,
}, { prefix: "sf." })
```

### `localStorage` (browser, sync)

Wrap synchronous APIs in an async shim:

```ts
const cache = createKvPullCache({
  get: async (key) => localStorage.getItem(key),
  set: async (key, value) => localStorage.setItem(key, value),
})
```

### Electron `electron-store`

```ts
import Store from "electron-store"
const store = new Store()

const cache = createKvPullCache({
  get: async (key) => store.get(key) as string ?? null,
  set: async (key, value) => store.set(key, value),
})
```

## TTL expiry

When `maxAgeMs` is set, each cached entry is stored as an envelope:

```json
{ "payload": "<the pull result JSON>", "_cachedAt": 1716000000000 }
```

On read, if `Date.now() - _cachedAt > maxAgeMs`, the entry is treated as a miss
(returns `null`). The stale value is **not** deleted from the KV store — the next
successful pull overwrites it.

## Error handling

All `get` and `set` operations are wrapped in `try/catch`. Errors from the KV store
are swallowed silently: a read error returns `null` (cache miss), a write error is
ignored. This ensures a broken or unavailable KV store never blocks normal sync
operations.

## Thread safety

The KV store's `get` and `set` are called independently. If multiple instances share
a KV store, the last writer wins — same as any pull cache. For single-writer setups
(one client per process) this is safe.
