/**
 * Cached sealed-blob store.
 *
 * Wraps the {@link ByteSealer} seal/push/pull core (over
 * `StarfishClient.pushBlob` / `pullBlob`) with two caches:
 *  - an in-memory decrypted-plaintext cache (default 64 MB budget, evicted in
 *    insertion order / FIFO under memory pressure), and
 *  - a KV-persisted cache of the stored (post-seal) ciphertext (default 4 MB)
 *    so blobs can be reopened offline / after a reload without a round-trip.
 *
 * The app supplies a {@link SealedBlobPaths} strategy that maps a blob id + an
 * app-defined context (e.g. `{ spaceId, nodeId }`) to the storage push/pull
 * paths and the seal AAD. The store owns id generation, size-guarding, sealing,
 * transport, and caching — so a consuming library keeps only its path/AAD config.
 */
import { getBase64, randomId } from "@drakkar.software/starfish-protocol"
import type { Base64Provider } from "@drakkar.software/starfish-protocol"

import type { StarfishClient } from "./client.js"
import type { ByteSealer } from "./blob-seal.js"

/** Minimal async KV interface for the persisted ciphertext cache. */
export interface SealedBlobStoreKv {
  getItem(key: string): Promise<string | null>
  setItem(key: string, value: string): Promise<void>
  removeItem(key: string): Promise<void>
}

/** Maps a blob id + app context to its storage paths and seal AAD. */
export interface SealedBlobPaths<Ctx> {
  /** Push path for the blob (starts with `/push/…`). */
  pushPath(id: string, ctx: Ctx): string
  /** Pull path for the blob (starts with `/pull/…`). Also used as the cache key. */
  pullPath(id: string, ctx: Ctx): string
  /** AAD bound into the seal — typically the storage name; blocks relocation. */
  aad(id: string, ctx: Ctx): string
}

/** A cached sealed-blob store bound to one path/AAD strategy. */
export interface SealedBlobStore<Ctx> {
  /**
   * Seal (when `sealer` is non-null) + upload `bytes`, minting and returning a
   * fresh blob id. Pass `sealer: null` for plaintext (public) blobs.
   * @throws {FileTooLargeError} if `bytes` exceeds `maxBytes`.
   */
  upload(client: StarfishClient, sealer: ByteSealer | null, bytes: Uint8Array, ctx: Ctx): Promise<string>
  /** Fetch + unseal a blob by id (memory → persisted → network). */
  load(client: StarfishClient, sealer: ByteSealer | null, id: string, ctx: Ctx): Promise<Uint8Array>
  /** Drop the in-memory decrypted cache. */
  clearCache(): void
}

/** Thrown when a payload exceeds the configured `maxBytes` before any upload. */
export class FileTooLargeError extends Error {
  readonly size: number
  readonly max: number
  constructor(size: number, max: number) {
    super(`File is ${size} bytes — maximum allowed is ${max} bytes`)
    this.name = "FileTooLargeError"
    this.size = size
    this.max = max
  }
}

/** Configuration for {@link createSealedBlobStore}. */
export interface CreateSealedBlobStoreOptions<Ctx> {
  /** Path + AAD strategy. */
  paths: SealedBlobPaths<Ctx>
  /** Maximum plaintext byte size for a single upload. */
  maxBytes: number
  /** KV adapter for the persisted ciphertext cache. Omit to disable persistence. */
  kvAdapter?: SealedBlobStoreKv
  /** KV key prefix for persisted ciphertext. Default: `"starfish.sealedblob."`. */
  persistPrefix?: string
  /** KV key for the persist index. Default: `"starfish.sealedblob.__index"`. */
  persistIndexKey?: string
  /** In-memory decrypted-cache budget in bytes. Default: 64 MB. `0` disables the
   *  in-memory cache entirely (each `load` fetches from persistence/network). */
  memBudgetBytes?: number
  /** Persisted ciphertext-cache budget in bytes. Default: 4 MB. */
  persistBudgetBytes?: number
  /** Base64 provider for the persisted cache. Default: `getBase64()`. */
  base64?: Base64Provider
  /** Blob id generator. Default: `randomId`. */
  genId?: () => string
}

const DEFAULT_MEM_BUDGET_BYTES = 64 * 1024 * 1024
const DEFAULT_PERSIST_BUDGET_BYTES = 4 * 1024 * 1024

type PersistIndex = { k: string; n: number }[]

/**
 * Create a cached {@link SealedBlobStore}. State (in-memory LRU) lives in the
 * returned instance's closure — create one per app scope.
 */
export function createSealedBlobStore<Ctx>(opts: CreateSealedBlobStoreOptions<Ctx>): SealedBlobStore<Ctx> {
  const { paths, maxBytes, kvAdapter } = opts
  const persistPrefix = opts.persistPrefix ?? "starfish.sealedblob."
  const persistIndexKey = opts.persistIndexKey ?? "starfish.sealedblob.__index"
  const memBudget = opts.memBudgetBytes ?? DEFAULT_MEM_BUDGET_BYTES
  const persistBudget = opts.persistBudgetBytes ?? DEFAULT_PERSIST_BUDGET_BYTES
  const b64 = () => opts.base64 ?? getBase64()
  const genId = opts.genId ?? randomId

  const useMemCache = memBudget > 0
  const decryptedCache = new Map<string, Uint8Array>()
  let cacheBytes = 0

  const cacheKey = (id: string, ctx: Ctx): string => paths.pullPath(id, ctx)

  function cachePut(key: string, bytes: Uint8Array): void {
    if (!useMemCache) return
    const existing = decryptedCache.get(key)
    if (existing) cacheBytes -= existing.length
    decryptedCache.set(key, bytes)
    cacheBytes += bytes.length
    for (const [k, v] of decryptedCache) {
      if (cacheBytes <= memBudget) break
      if (k === key) continue
      decryptedCache.delete(k)
      cacheBytes -= v.length
    }
  }

  const persistStoreKey = (key: string): string => `${persistPrefix}${key}`

  async function readPersistIndex(): Promise<PersistIndex> {
    if (!kvAdapter) return []
    const raw = await kvAdapter.getItem(persistIndexKey).catch(() => null)
    if (!raw) return []
    try {
      const parsed = JSON.parse(raw) as unknown
      return Array.isArray(parsed) ? (parsed as PersistIndex) : []
    } catch {
      return []
    }
  }

  async function persistGet(key: string): Promise<Uint8Array | null> {
    if (!kvAdapter) return null
    const b = await kvAdapter.getItem(persistStoreKey(key)).catch(() => null)
    if (!b) return null
    try {
      return b64().decode(b)
    } catch {
      return null
    }
  }

  async function persistPut(key: string, stored: Uint8Array): Promise<void> {
    if (!kvAdapter) return
    const storeKey = persistStoreKey(key)
    const encoded = b64().encode(stored)
    const index = (await readPersistIndex()).filter((e) => e.k !== storeKey)
    index.push({ k: storeKey, n: encoded.length })
    let total = index.reduce((s, e) => s + e.n, 0)
    while (total > persistBudget && index.length > 1) {
      const victim = index.shift()!
      if (victim.k === storeKey) {
        index.push(victim)
        continue
      }
      await kvAdapter.removeItem(victim.k).catch(() => {})
      total -= victim.n
    }
    await kvAdapter.setItem(storeKey, encoded).catch(() => {})
    await kvAdapter.setItem(persistIndexKey, JSON.stringify(index)).catch(() => {})
  }

  return {
    async upload(client, sealer, bytes, ctx) {
      if (bytes.length > maxBytes) throw new FileTooLargeError(bytes.length, maxBytes)
      const id = genId()
      const aad = paths.aad(id, ctx)
      const stored = sealer ? await sealer.sealBytes(bytes, aad) : bytes
      await client.pushBlob(paths.pushPath(id, ctx), stored, "application/octet-stream")
      const key = cacheKey(id, ctx)
      cachePut(key, bytes)
      await persistPut(key, stored)
      return id
    },
    async load(client, sealer, id, ctx) {
      const key = cacheKey(id, ctx)
      const hit = decryptedCache.get(key)
      if (hit) return hit
      let stored = await persistGet(key)
      if (!stored) {
        const res = await client.pullBlob(paths.pullPath(id, ctx))
        stored = new Uint8Array(res.data)
        await persistPut(key, stored)
      }
      const aad = paths.aad(id, ctx)
      const bytes = sealer ? await sealer.openBytes(stored, aad) : stored
      cachePut(key, bytes)
      return bytes
    },
    clearCache() {
      decryptedCache.clear()
      cacheBytes = 0
    },
  }
}
