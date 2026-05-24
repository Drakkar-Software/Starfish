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
