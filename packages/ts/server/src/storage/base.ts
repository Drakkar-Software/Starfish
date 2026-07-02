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
  /**
   * OPTIONAL compare-and-swap support. A backend that implements BOTH
   * {@link getWithEtag} and {@link putIfMatch} gains cross-instance
   * concurrency safety for append-only writes (see `appendItem`): the head
   * write becomes an atomic compare-and-swap that FAILS instead of silently
   * overwriting a concurrent write from another server instance sharing the
   * same bucket. Backends that leave these undefined keep the previous
   * last-write-wins behaviour — safe for a single instance, but a shared
   * bucket may drop a concurrent instance's append.
   *
   * Read the current value together with an opaque version tag (`etag`).
   * Returns `null` when the key is absent.
   */
  getWithEtag?(key: string, context?: StoreContext): Promise<{ value: string; etag: string } | null>
  /**
   * Atomic conditional write. Stores `body` only if the key's current version
   * matches `expectedEtag` — or, when `expectedEtag` is `null`, only if the key
   * does not yet exist. Returns the new etag on success, or `null` when the
   * precondition failed because a concurrent writer changed the key.
   */
  putIfMatch?(
    key: string,
    body: string,
    expectedEtag: string | null,
    opts?: { contentType?: string; cacheControl?: string },
    context?: StoreContext,
  ): Promise<string | null>
  getBytes?(key: string, context?: StoreContext): Promise<{ body: Uint8Array; contentType: string } | null>
  putBytes?(
    key: string,
    body: Uint8Array,
    opts: { contentType: string; cacheControl?: string },
    context?: StoreContext,
  ): Promise<void>
}
