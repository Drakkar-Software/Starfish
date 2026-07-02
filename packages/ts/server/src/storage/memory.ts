import type { ObjectStore, StoreContext } from "./base.js"

const _globalData = new Map<string, string>()

/**
 * Content-derived version tag for compare-and-swap. It is store-internal (never
 * crosses the wire, never compared across languages), so any stable hash works.
 * Deriving it from content means MemoryObjectStore instances sharing one backing
 * Map agree on the etag with zero extra shared state. (ABA is not a concern for
 * `appendItem`: an append strictly grows the element count, so the head content
 * never returns to a prior value.)
 */
function etagOfString(body: string): string {
  // FNV-1a 32-bit, salted with length to shrink collision odds.
  let h = 0x811c9dc5
  for (let i = 0; i < body.length; i++) {
    h ^= body.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return `${body.length}-${(h >>> 0).toString(16)}`
}

export class MemoryObjectStore implements ObjectStore {
  private _data: Map<string, string>
  private _binary = new Map<string, Uint8Array>()
  private _binaryMeta = new Map<string, string>()

  constructor(data?: Map<string, string>) {
    this._data = data ?? _globalData
  }

  async getString(key: string, _context?: StoreContext): Promise<string | null> {
    return this._data.get(key) ?? null
  }

  async put(key: string, body: string, _opts?: { contentType?: string; cacheControl?: string }, _context?: StoreContext): Promise<void> {
    this._data.set(key, body)
  }

  async getWithEtag(key: string, _context?: StoreContext): Promise<{ value: string; etag: string } | null> {
    const value = this._data.get(key)
    if (value === undefined) return null
    return { value, etag: etagOfString(value) }
  }

  async putIfMatch(
    key: string,
    body: string,
    expectedEtag: string | null,
    _opts?: { contentType?: string; cacheControl?: string },
    _context?: StoreContext,
  ): Promise<string | null> {
    const current = this._data.get(key)
    const currentEtag = current === undefined ? null : etagOfString(current)
    // Precondition failed → a concurrent writer changed the key. Do NOT overwrite.
    if (currentEtag !== expectedEtag) return null
    this._data.set(key, body)
    return etagOfString(body)
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    _context?: StoreContext,
  ): Promise<string[]> {
    // Union both maps: put() and putBytes() share one logical key namespace
    // (same as the real S3/filesystem backends), so a binary-written key must
    // be listable too.
    const allKeys = new Set<string>([...this._data.keys(), ...this._binary.keys()])
    let keys = [...allKeys].filter((k) => k.startsWith(prefix)).sort()
    if (opts?.startAfter) {
      keys = keys.filter((k) => k > opts.startAfter!)
    }
    if (opts?.limit) {
      keys = keys.slice(0, opts.limit)
    }
    return keys
  }

  async getBytes(key: string, _context?: StoreContext): Promise<{ body: Uint8Array; contentType: string } | null> {
    const body = this._binary.get(key)
    if (!body) return null
    return { body, contentType: this._binaryMeta.get(key) ?? "application/octet-stream" }
  }

  async putBytes(
    key: string,
    body: Uint8Array,
    opts: { contentType: string },
    _context?: StoreContext,
  ): Promise<void> {
    this._binary.set(key, body)
    this._binaryMeta.set(key, opts.contentType)
  }

  async delete(key: string, _context?: StoreContext): Promise<void> {
    this._data.delete(key)
    this._binary.delete(key)
    this._binaryMeta.delete(key)
  }

  async deleteMany(keys: string[], _context?: StoreContext): Promise<void> {
    for (const key of keys) {
      this._data.delete(key)
      this._binary.delete(key)
      this._binaryMeta.delete(key)
    }
  }
}

type MaybeAsync<T> = T | Promise<T>

type GetFn = (key: string, context?: StoreContext) => MaybeAsync<string | null>
type PutFn = (key: string, body: string, context?: StoreContext) => MaybeAsync<void>
type ListFn = (
  prefix: string,
  startAfter: string | undefined,
  limit: number | undefined,
  context?: StoreContext,
) => MaybeAsync<string[]>
type DeleteFn = (key: string, context?: StoreContext) => MaybeAsync<void>

export class CustomObjectStore implements ObjectStore {
  private _onGet?: GetFn
  private _onPut?: PutFn
  private _onList?: ListFn
  private _onDelete?: DeleteFn

  constructor(opts: {
    onGet?: GetFn
    onPut?: PutFn
    onList?: ListFn
    onDelete?: DeleteFn
  }) {
    this._onGet = opts.onGet
    this._onPut = opts.onPut
    this._onList = opts.onList
    this._onDelete = opts.onDelete
  }

  async getString(key: string, context?: StoreContext): Promise<string | null> {
    if (!this._onGet) return null
    return this._onGet(key, context)
  }

  async put(key: string, body: string, _opts?: { contentType?: string; cacheControl?: string }, context?: StoreContext): Promise<void> {
    if (this._onPut) await this._onPut(key, body, context)
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    context?: StoreContext,
  ): Promise<string[]> {
    if (!this._onList) return []
    return this._onList(prefix, opts?.startAfter, opts?.limit, context)
  }

  async delete(key: string, context?: StoreContext): Promise<void> {
    if (this._onDelete) await this._onDelete(key, context)
  }

  async deleteMany(keys: string[], context?: StoreContext): Promise<void> {
    for (const key of keys) {
      await this.delete(key, context)
    }
  }
}
