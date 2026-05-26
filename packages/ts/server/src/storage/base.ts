export interface StoreContext {
  collection: string
  namespace?: string
  params: Readonly<Record<string, string>>
  identity: string | null
  roles: readonly string[]
  action: "pull" | "push" | "list" | "delete"
}

export interface ObjectStore {
  getString(key: string, context?: StoreContext): Promise<string | null>
  put(
    key: string,
    body: string,
    opts?: { contentType?: string; cacheControl?: string },
    context?: StoreContext,
  ): Promise<void>
  /**
   * Return EVERY key under `prefix`, in ascending lexicographic order, unless
   * `opts.limit` caps the count. The segmented append-only log depends on both
   * guarantees: it lists all of a document's chunk keys in one call (no
   * `limit`) and binary-searches them by string compare, so a backend that
   * truncates (e.g. an S3 page cap) or returns keys out of order would yield
   * incomplete or misordered data. Custom backends must paginate fully and sort.
   */
  listKeys(
    prefix: string,
    opts?: { startAfter?: string; limit?: number },
    context?: StoreContext,
  ): Promise<string[]>
  delete(key: string, context?: StoreContext): Promise<void>
  deleteMany(keys: string[], context?: StoreContext): Promise<void>
  getBytes?(key: string, context?: StoreContext): Promise<{ body: Uint8Array; contentType: string } | null>
  putBytes?(
    key: string,
    body: Uint8Array,
    opts: { contentType: string; cacheControl?: string },
    context?: StoreContext,
  ): Promise<void>
}
