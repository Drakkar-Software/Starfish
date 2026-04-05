import type { ObjectStore } from "./base.js"

const _globalData = new Map<string, string>()

export class MemoryObjectStore implements ObjectStore {
  private _data: Map<string, string>
  private _binary = new Map<string, Uint8Array>()
  private _binaryMeta = new Map<string, string>()

  constructor(data?: Map<string, string>) {
    this._data = data ?? _globalData
  }

  async getString(key: string): Promise<string | null> {
    return this._data.get(key) ?? null
  }

  async put(key: string, body: string): Promise<void> {
    this._data.set(key, body)
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    let keys = [...this._data.keys()].filter((k) => k.startsWith(prefix)).sort()
    if (opts?.startAfter) {
      keys = keys.filter((k) => k > opts.startAfter!)
    }
    if (opts?.limit) {
      keys = keys.slice(0, opts.limit)
    }
    return keys
  }

  async getBytes(key: string): Promise<{ body: Uint8Array; contentType: string } | null> {
    const body = this._binary.get(key)
    if (!body) return null
    return { body, contentType: this._binaryMeta.get(key) ?? "application/octet-stream" }
  }

  async putBytes(
    key: string,
    body: Uint8Array,
    opts: { contentType: string },
  ): Promise<void> {
    this._binary.set(key, body)
    this._binaryMeta.set(key, opts.contentType)
  }

  async delete(key: string): Promise<void> {
    this._data.delete(key)
    this._binary.delete(key)
    this._binaryMeta.delete(key)
  }

  async deleteMany(keys: string[]): Promise<void> {
    for (const key of keys) {
      this._data.delete(key)
      this._binary.delete(key)
      this._binaryMeta.delete(key)
    }
  }
}

type MaybeAsync<T> = T | Promise<T>

type GetFn = (key: string) => MaybeAsync<string | null>
type PutFn = (key: string, body: string) => MaybeAsync<void>
type ListFn = (
  prefix: string,
  startAfter: string | undefined,
  limit: number | undefined,
) => MaybeAsync<string[]>
type DeleteFn = (key: string) => MaybeAsync<void>

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

  async getString(key: string): Promise<string | null> {
    if (!this._onGet) return null
    return this._onGet(key)
  }

  async put(key: string, body: string): Promise<void> {
    if (this._onPut) await this._onPut(key, body)
  }

  async listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    if (!this._onList) return []
    return this._onList(prefix, opts?.startAfter, opts?.limit)
  }

  async delete(key: string): Promise<void> {
    if (this._onDelete) await this._onDelete(key)
  }

  async deleteMany(keys: string[]): Promise<void> {
    for (const key of keys) {
      await this.delete(key)
    }
  }
}
