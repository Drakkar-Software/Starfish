export type EncryptionMode = "none" | "identity" | "server" | "delegated"

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
}

export interface CollectionRateLimitConfig {
  windowMs?: number
  maxRequests?: number
}

export interface FieldPermission {
  readRoles?: string[]
  writeRoles?: string[]
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
  /** Document time-to-live in milliseconds. Expired documents return empty data on pull. */
  ttlMs?: number
  /** Per-field read/write permissions. Keys are top-level field names. */
  fieldPermissions?: Record<string, FieldPermission>
}

export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
}

export interface SyncConfig {
  version: 1
  collections: CollectionConfig[]
  rateLimit?: RateLimitConfig
}
