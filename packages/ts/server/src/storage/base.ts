export interface ObjectStore {
  getString(key: string): Promise<string | null>
  put(
    key: string,
    body: string,
    opts?: { contentType?: string; cacheControl?: string },
  ): Promise<void>
  listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
  ): Promise<string[]>
  delete(key: string): Promise<void>
  deleteMany(keys: string[]): Promise<void>
  getBytes?(key: string): Promise<{ body: Uint8Array; contentType: string } | null>
  putBytes?(
    key: string,
    body: Uint8Array,
    opts: { contentType: string; cacheControl?: string },
  ): Promise<void>
}
