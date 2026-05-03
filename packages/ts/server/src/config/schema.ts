export type EncryptionMode = "none" | "identity" | "server" | "delegated" | "group"

export type WriteMode = "pull_only" | "push_through" | "bidirectional" | "push_only"

export type SyncTrigger = "scheduled" | "on_pull"

export interface RemoteConfig {
  url: string
  pullPath: string
  pushPath?: string
  intervalMs: number
  headers: Record<string, string>
  writeMode: WriteMode
  syncTriggers: SyncTrigger[]
  onPullMinIntervalMs?: number
}

export interface QueueConfig {
  topic?: string
  includeParams: boolean
  includeBody?: boolean
}

export interface CollectionRateLimitConfig {
  windowMs?: number
  maxRequests?: number
}

export interface FieldPermission {
  readRoles?: string[]
  writeRoles?: string[]
}

export interface AppendOnlyConfig {
  /** Array field name in the stored document. Defaults to "items". */
  field?: string
  /** true (default) — append item to stored array.
   *  false — compute hash and publish to queue without writing to storage (replaces queueOnly). */
  persist?: boolean
  /** When true, validates the client's baseHash against hash(lastItem) before appending.
   *  Returns 409 if the last item has changed since the client last read. */
  checkLastItem?: boolean
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
  clientEncrypted?: boolean
  bundle?: string
  remote?: RemoteConfig
  queue?: QueueConfig
  /** When set, every push appends the incoming data object as the last item of a stored array.
   *  Pass `true` as shorthand for `{}` (all defaults). */
  appendOnly?: AppendOnlyConfig
  /** Document time-to-live in milliseconds. Expired documents return empty data on pull. */
  ttlMs?: number
  /** Per-field read/write permissions. Keys are top-level field names. */
  fieldPermissions?: Record<string, FieldPermission>
  /** Base64-encoded public key exposed via the /config endpoint for client-side encryption. */
  publicKey?: string
  /** When true, exposes a GET /list/... endpoint that returns the keys of existing documents
   *  under this collection's prefix. The last path parameter in storagePath is the one being
   *  enumerated. Requires at least one path parameter; incompatible with appendOnly and bundle. */
  listable?: boolean
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
