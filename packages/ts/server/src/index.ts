// Storage
export { AbstractObjectStore } from "./storage/base.js"
export { MemoryObjectStore, CustomObjectStore } from "./storage/memory.js"
export { FilesystemObjectStore, type FilesystemStorageOptions } from "./storage/filesystem.js"

// Protocol
export { pull } from "./protocol/pull.js"
export { push, type Author } from "./protocol/push.js"
export { computeTimestamps, filterByCheckpoint } from "./protocol/timestamps.js"
export {
  DOCUMENT_VERSION,
  isPushConflict,
  type StoredDocument,
  type Timestamps,
  type PushResult,
  type PushConflict,
} from "./protocol/types.js"

// Encryption
export { EncryptedObjectStore } from "./encryption/encrypted_store.js"

// Config
export type {
  SyncConfig,
  CollectionConfig,
  CollectionRateLimitConfig,
  RateLimitConfig,
  EncryptionMode,
  WriteMode,
  SyncTrigger,
  RemoteConfig,
} from "./config/schema.js"
export { validateConfig } from "./config/validate.js"
export { parseConfigJson, loadConfig, saveConfig } from "./config/loader.js"

// Router
export {
  createSyncRouter,
  type SyncRouterOptions,
  type AuthResult,
  type RoleResolver,
  type RoleEnricher,
} from "./router/route_builder.js"
export {
  handleSyncPull,
  handleSyncPush,
  validatePathSegment,
  validateUrlNotPrivate,
  deepSanitize,
  parseCheckpoint,
  type SignatureVerifier,
} from "./router/helpers.js"
export { checkBodyLimit, RateLimiter } from "./router/middleware.js"
export { matchesAllowedMime, isJsonCollection } from "./router/mime.js"

// Replica
export { ReplicaManager } from "./replica/manager.js"
export { NotificationPublisher, verifySignature } from "./replica/notifier.js"
export { SubscriptionStore, type Subscription } from "./replica/subscriber.js"

// Errors
export { StartupError, AuthError, ConflictError, NotFoundError } from "./errors.js"

// Constants
export * from "./constants.js"
