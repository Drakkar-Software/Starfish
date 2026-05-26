export type EncryptionMode = "none" | "delegated"

export interface CollectionRateLimitConfig {
  windowMs?: number
  maxRequests?: number
}

export interface FieldPermission {
  readRoles?: string[]
  writeRoles?: string[]
}

/** Append-only strategy. Tagged by `type` so new strategies can be added later;
 *  only `"by_timestamp"` is supported today (each element is stored as `{ts, data}`
 *  and pulls filter by `ts` via `?checkpoint=`). */
export interface AppendOnlyConfig {
  /** Discriminator. Only `"by_timestamp"` is currently supported. */
  type: "by_timestamp"
  /** Array field name in the stored document. Defaults to "items". */
  field?: string
  /** true (default) — append the incoming item to the stored array as `{ts, data}`.
   *  false — compute a hash and emit a write event without writing to storage
   *  (consumed by a plugin such as starfish-queuing; replaces queueOnly). */
  persist?: boolean
  /** Opt-in cap: reject an append once the stored element count has reached this
   *  many, with `409 { error: "append_limit_exceeded", limit }`. Unset = unlimited.
   *  Bounds a single document; for higher volume, partition by a path parameter
   *  (e.g. `storagePath: "events/{date}"`). Requires `persist` (the default). */
  maxItems?: number
  /** Opt-in segmented storage: store the log as fixed-size sealed chunks of this
   *  many elements (plus a small head document) instead of one growing blob. Bounds
   *  append cost to O(chunkSize) (no O(n²) build) and lets `?checkpoint=`/`?last=`
   *  pulls read only the chunks they need. Unset = single-document (legacy) layout.
   *  Recommended ~10000. Server-internal only — the wire format is unchanged.
   *  Requires `persist` (the default). */
  chunkSize?: number
}

export interface CollectionConfig {
  name: string
  storagePath: string
  readRoles: string[]
  writeRoles: string[]
  encryption: EncryptionMode
  maxBodyBytes: number
  rateLimit?: CollectionRateLimitConfig | null
  cacheDurationMs?: number
  objectSchema?: Record<string, unknown>
  allowedMimeTypes: string[]
  pullOnly?: boolean
  pushOnly?: boolean
  forceFullFetch?: boolean
  bundle?: string
  /** When set, every push appends the incoming `data` as the last element of a stored array,
   *  recorded as `{ts, data}`. Pass `true` as shorthand for `{ type: "by_timestamp" }`. */
  appendOnly?: AppendOnlyConfig
  /** Document time-to-live in milliseconds. Expired documents return empty data on pull. */
  ttlMs?: number
  /** Per-field read/write permissions. Keys are top-level field names. */
  fieldPermissions?: Record<string, FieldPermission>
  /** Optional override for the keyring storage path. When omitted, defaults to
   *  `<storagePath>/_keyring`. Only relevant for `"delegated"` encryption. */
  keyringPath?: string
  /** When true, exposes a GET /list/... endpoint that returns the keys of existing documents
   *  under this collection's prefix. The last path parameter in storagePath is the one being
   *  enumerated. Requires at least one path parameter; incompatible with appendOnly and bundle. */
  listable?: boolean
  /** When true, only the **root device** (a self-signed device cap, `iss === sub`) may access
   *  this collection; every paired/delegated device cap and member cap is rejected with 403,
   *  in addition to the normal readRoles/writeRoles checks. Incompatible with public
   *  read/write roles (rejected at config load). */
  rootOnly?: boolean
}

export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
}

export interface NamespaceConfig {
  collections: CollectionConfig[]
}

export interface SyncConfig {
  version: 1
  collections: CollectionConfig[]
  /**
   * Named sub-routers. Each key becomes a URL prefix: `/{name}/pull/...` and `/{name}/push/...`.
   * Keys must match `[a-zA-Z0-9_-]+` and must not be `pull`, `push`, `health`, or `batch`.
   * Each namespace must contain at least one collection.
   */
  namespaces?: Record<string, NamespaceConfig>
  rateLimit?: RateLimitConfig
}
