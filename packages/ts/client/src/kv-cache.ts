/**
 * KV-backed {@link PullCache} factory.
 *
 * {@link createKvPullCache} adapts any {@link AsyncStateStorage} (or any
 * object with `getItem`/`setItem`) into a {@link PullCache} that the
 * `StarfishClient` can use as its offline read-through cache.
 *
 * Why this matters: the client's `cache` option is ciphertext-at-rest by
 * construction — it stores the raw sealed server response and only decrypts
 * in memory on read. Backing the cache with the platform's own KV (AsyncStorage
 * on React Native, IndexedDB via `createIndexedDBStorage`, a custom adapter)
 * gives offline-first reads without exposing plaintext to the OS storage layer.
 *
 * @example
 * ```ts
 * import AsyncStorage from "@react-native-async-storage/async-storage"
 * import { StarfishClient } from "@drakkar.software/starfish-client"
 * import { createKvPullCache } from "@drakkar.software/starfish-client"
 *
 * const client = new StarfishClient({
 *   baseUrl: "https://api.example.com",
 *   cache: createKvPullCache(AsyncStorage, { prefix: "sf:", maxAgeMs: 30 * 24 * 60 * 60 * 1000 }),
 * })
 * ```
 */
import type { PullCache } from "./types.js"

/** A storage backend that `createKvPullCache` can wrap. */
export interface KvStore {
  getItem(key: string): Promise<string | null> | string | null
  setItem(key: string, value: string): Promise<unknown> | unknown
  removeItem?: (key: string) => Promise<unknown> | unknown
}

/** Options for {@link createKvPullCache}. */
export interface KvPullCacheOptions {
  /**
   * Key prefix for cache entries (default `"starfish.pullcache."`). Change
   * when sharing a KV store with other data to avoid key collisions.
   */
  prefix?: string
  /**
   * Maximum age in milliseconds for a cached snapshot. When set, an entry
   * older than `maxAgeMs` is returned as `null` (a cache MISS) so the next
   * pull goes to the network rather than serving arbitrarily stale data.
   *
   * Each entry stores a `_cachedAt` wall-clock timestamp; expiry is checked on
   * every `get`. Omit (default) for entries that never expire — recommended
   * for offline-first apps where any last-synced data beats none.
   */
  maxAgeMs?: number
}

interface CacheEntry {
  payload: string
  _cachedAt: number
}

/**
 * Adapt a KV store into a {@link PullCache} for `StarfishClient`.
 *
 * The adapter serialises the cached pull payload (itself a JSON string) into
 * an outer JSON envelope that tracks the wall-clock write time for optional
 * max-age expiry. Reading a legacy entry without `_cachedAt` treats it as
 * fresh (backward-compatible with plain-string caches).
 *
 * All `get`/`set` errors are swallowed (the {@link PullCache} contract
 * requires implementations not to throw) — a failing KV store simply
 * degrades to "no cache" without crashing the app.
 */
export function createKvPullCache(kv: KvStore, opts: KvPullCacheOptions = {}): PullCache {
  const prefix = opts.prefix ?? "starfish.pullcache."
  const maxAgeMs = opts.maxAgeMs

  return {
    async get(key: string): Promise<string | null> {
      try {
        const raw = await kv.getItem(prefix + key)
        if (raw === null || raw === undefined) return null

        // Try to read the new envelope format `{"payload":"…","_cachedAt":n}`.
        // Fall back to treating the raw string as the payload directly for
        // backward-compatibility with plain-string caches written before this
        // library was used.
        let payload: string
        let cachedAt: number | undefined
        try {
          const envelope = JSON.parse(raw) as Partial<CacheEntry>
          if (typeof envelope.payload === "string") {
            payload = envelope.payload
            cachedAt = envelope._cachedAt
          } else {
            // Plain-string format: the raw value is the payload.
            payload = raw
          }
        } catch {
          payload = raw
        }

        if (maxAgeMs !== undefined && cachedAt !== undefined) {
          if (Date.now() - cachedAt > maxAgeMs) return null
        }

        return payload
      } catch {
        return null
      }
    },

    async set(key: string, value: string): Promise<void> {
      try {
        const envelope: CacheEntry = { payload: value, _cachedAt: Date.now() }
        await kv.setItem(prefix + key, JSON.stringify(envelope))
      } catch {
        // Swallow — storage failures degrade to "no cache", not a crash.
      }
    },
  }
}
