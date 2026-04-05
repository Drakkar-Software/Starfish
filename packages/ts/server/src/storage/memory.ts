import { AbstractObjectStore } from "./base.js"

export class MemoryObjectStore extends AbstractObjectStore {
  private readonly _data: Record<string, string>
  private readonly _binary: Record<string, Buffer>
  private readonly _binaryMeta: Record<string, string>

  constructor(options?: { data?: Record<string, string> }) {
    super()
    this._data = options?.data ?? {}
    this._binary = {}
    this._binaryMeta = {}
  }

  async getString(key: string): Promise<string | null> {
    return this._data[key] ?? null
  }

  async put(
    key: string,
    body: string,
    _options?: { contentType?: string; cacheControl?: string },
  ): Promise<void> {
    this._data[key] = body
  }

  async listKeys(
    prefix: string,
    options?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    let keys = Object.keys(this._data)
      .filter((k) => k.startsWith(prefix))
      .sort()
    if (options?.startAfter) {
      keys = keys.filter((k) => k > options.startAfter!)
    }
    if (options?.limit !== undefined) {
      keys = keys.slice(0, options.limit)
    }
    return keys
  }

  async delete(key: string): Promise<void> {
    delete this._data[key]
    delete this._binary[key]
    delete this._binaryMeta[key]
  }

  async deleteMany(keys: string[]): Promise<void> {
    for (const key of keys) {
      await this.delete(key)
    }
  }

  async getBytes(key: string): Promise<{ data: Buffer; contentType: string } | null> {
    const data = this._binary[key]
    if (!data) return null
    return { data, contentType: this._binaryMeta[key] ?? "application/octet-stream" }
  }

  async putBytes(
    key: string,
    body: Buffer,
    options: { contentType: string; cacheControl?: string },
  ): Promise<void> {
    this._binary[key] = body
    this._binaryMeta[key] = options.contentType
  }
}

type MaybeAsync<T> = T | Promise<T>

export class CustomObjectStore extends AbstractObjectStore {
  constructor(
    private readonly callbacks: {
      onGet: (key: string) => MaybeAsync<string | null>
      onPut: (key: string, body: string, options?: { contentType?: string }) => MaybeAsync<void>
      onList: (
        prefix: string,
        options?: { startAfter?: string; limit?: number },
      ) => MaybeAsync<string[]>
      onDelete: (key: string) => MaybeAsync<void>
    },
  ) {
    super()
  }

  async getString(key: string): Promise<string | null> {
    return this.callbacks.onGet(key)
  }

  async put(
    key: string,
    body: string,
    options?: { contentType?: string; cacheControl?: string },
  ): Promise<void> {
    return this.callbacks.onPut(key, body, options)
  }

  async listKeys(
    prefix: string,
    options?: { startAfter?: string; limit?: number },
  ): Promise<string[]> {
    return this.callbacks.onList(prefix, options)
  }

  async delete(key: string): Promise<void> {
    return this.callbacks.onDelete(key)
  }

  async deleteMany(keys: string[]): Promise<void> {
    for (const key of keys) {
      await this.delete(key)
    }
  }
}
