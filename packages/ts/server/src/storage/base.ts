export interface BinaryMeta {
  contentType: string
}

export abstract class AbstractObjectStore {
  abstract getString(key: string): Promise<string | null>
  abstract put(
    key: string,
    body: string,
    options?: { contentType?: string; cacheControl?: string },
  ): Promise<void>
  abstract listKeys(
    prefix: string,
    options?: { startAfter?: string; limit?: number },
  ): Promise<string[]>
  abstract delete(key: string): Promise<void>
  abstract deleteMany(keys: string[]): Promise<void>

  async getBytes(key: string): Promise<{ data: Buffer; contentType: string } | null> {
    throw new Error("getBytes not supported by this store")
  }

  async putBytes(
    key: string,
    body: Buffer,
    options: { contentType: string; cacheControl?: string },
  ): Promise<void> {
    throw new Error("putBytes not supported by this store")
  }
}
