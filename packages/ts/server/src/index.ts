// Config
export type {
  SyncConfig,
  CollectionConfig,
  NamespaceConfig,
  RemoteConfig,
  QueueConfig,
  CollectionRateLimitConfig,
  RateLimitConfig,
  EncryptionMode,
  WriteMode,
  SyncTrigger,
  FieldPermission,
} from "./config/schema.js"
export { validateConfig } from "./config/validate.js"
export { parseConfigJson, loadConfig, saveConfig } from "./config/loader.js"

// Storage
export type { ObjectStore } from "./storage/base.js"
export { MemoryObjectStore, CustomObjectStore } from "./storage/memory.js"

// Encryption
export { EncryptedObjectStore } from "./encryption/encrypted-store.js"

// Protocol
export type {
  StoredDocument,
  Timestamps,
  PullResult,
  PushSuccess,
  PushConflict,
  PushResult,
} from "./protocol/types.js"
export { DOCUMENT_VERSION } from "./protocol/types.js"
export { computeTimestamps, filterByCheckpoint } from "./protocol/timestamps.js"
export { pull } from "./protocol/pull.js"
export { push, type Author } from "./protocol/push.js"

// Router
export {
  createSyncRouter,
  setAjv,
  type SyncRouterOptions,
  type AuthResult,
  type RoleResolver,
  type RoleEnricher,
} from "./router/route-builder.js"
export type { SignatureVerifier } from "./router/helpers.js"
export {
  handleSyncPull,
  handleSyncPush,
  validatePathSegment,
  validateUrlNotPrivate,
  deepSanitize,
} from "./router/helpers.js"
export {
  checkBodyLimit,
  RateLimiter,
  corsMiddleware,
  securityHeadersMiddleware,
  requestTimeoutMiddleware,
  type CorsConfig,
  type SecurityHeadersConfig,
} from "./router/middleware.js"
export { matchesAllowedMime, isJsonCollection } from "./router/mime.js"

// Queue
export type { Queue } from "./queue/base.js"
export { MemoryQueue, CustomQueue } from "./queue/memory.js"

// Replica
export { ReplicaManager } from "./replica/manager.js"

// Lifecycle
export { createGracefulShutdown, type GracefulShutdownOptions, type ShutdownHandle } from "./lifecycle.js"

// Logger
export { createConsoleLogger, createJsonLogger, createNoopLogger, type LogLevel, type LogEntry, type ServerLogger } from "./logger.js"

// Audit
export { createConsoleAuditLogger, createCallbackAuditLogger, createNoopAuditLogger, type AuditEntry, type AuditLogger } from "./audit.js"

// TTL
export { isExpired } from "./ttl.js"

// OpenAPI
export { generateOpenApiSpec } from "./openapi.js"

// Errors
export { StartupError, AuthError, ConflictError, NotFoundError } from "./errors.js"

// Constants
export {
  ROLE_PUBLIC,
  ROLE_SELF,
  OP_READ,
  OP_WRITE,
  ENCRYPTION_NONE,
  ENCRYPTION_IDENTITY,
  ENCRYPTION_SERVER,
  ENCRYPTION_DELEGATED,
  ACTION_PULL,
  ACTION_PUSH,
  IDENTITY_PARAM,
  IDENTITY_KEY,
  QUERY_CHECKPOINT,
  HKDF_INFO_DEFAULT,
  HKDF_INFO_IDENTITY,
  HKDF_INFO_SERVER,
  DEFAULT_CONFIG_KEY,
  ERROR_HASH_MISMATCH,
  CONTENT_TYPE_JSON,
} from "./constants.js"
