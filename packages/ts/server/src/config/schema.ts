export type EncryptionMode = "none" | "identity" | "server" | "delegated"

export type WriteMode = "pull_only" | "push_through" | "bidirectional" | "push_only"

export type SyncTrigger = "scheduled" | "webhook" | "on_pull"

export interface RemoteConfig {
  url: string
  pullPath: string
  pushPath?: string
  intervalMs?: number
  headers?: Record<string, string>
  writeMode?: WriteMode
  syncTriggers?: SyncTrigger[]
  webhookSecret?: string
  onPullMinIntervalMs?: number
}

export interface CollectionRateLimitConfig {
  windowMs?: number
  maxRequests?: number
}

export interface CollectionConfig {
  name: string
  storagePath: string
  readRoles?: string[]
  writeRoles?: string[]
  encryption?: EncryptionMode
  maxBodyBytes?: number
  rateLimit?: CollectionRateLimitConfig | boolean
  cacheDurationMs?: number
  objectSchema?: Record<string, unknown>
  allowedMimeTypes?: string[]
  pullOnly?: boolean
  pushOnly?: boolean
  forceFullFetch?: boolean
  clientEncrypted?: boolean
  bundle?: string
  remote?: RemoteConfig
}

export interface RateLimitConfig {
  windowMs?: number
  maxRequests?: number
}

export interface SyncConfig {
  version: 1
  collections: CollectionConfig[]
  rateLimit?: RateLimitConfig
}
