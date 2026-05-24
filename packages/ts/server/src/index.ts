// Config
export type {
  SyncConfig,
  CollectionConfig,
  NamespaceConfig,
  CollectionRateLimitConfig,
  RateLimitConfig,
  EncryptionMode,
  FieldPermission,
} from "./config/schema.js"
export { validateConfig, collectConfigWarnings } from "./config/validate.js"
export { parseConfigJson, loadConfig, saveConfig } from "./config/loader.js"

// Storage
export type { ObjectStore, StoreContext } from "./storage/base.js"
export { MemoryObjectStore, CustomObjectStore } from "./storage/memory.js"

// Protocol
export type {
  StoredDocument,
  AppendElement,
  PullResult,
  PushSuccess,
  PushConflict,
  PushResult,
} from "./protocol/types.js"
export { DOCUMENT_VERSION } from "./protocol/types.js"
export { pull } from "./protocol/pull.js"
export { push, appendItem, type Author, type AppendConflict, type AppendOutcome } from "./protocol/push.js"

// Router
export {
  createSyncRouter,
  setAjv,
  type SyncRouterOptions,
  type AuthResult,
  type RoleResolver,
  type RoleEnricher,
  type ConfigEndpointOptions,
  type CollectionClientInfo,
  type ConfigResponse,
} from "./router/route-builder.js"
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

// Enrichers
export { composeEnrichers } from "./enrichers/compose.js"

// Lifecycle
export { createGracefulShutdown, type GracefulShutdownOptions, type ShutdownHandle } from "./lifecycle.js"

// Logger
export { createConsoleLogger, createJsonLogger, createNoopLogger, type LogLevel, type LogEntry, type ServerLogger } from "./logger.js"

// TTL
export { isExpired } from "./ttl.js"

// OpenAPI
export { generateOpenApiSpec } from "./openapi.js"

// Cap-cert auth (v3, opt-in)
export {
  createInMemoryNonceCache,
  type NonceCache,
  type NonceCacheOptions,
} from "./auth/nonce-cache.js"
export {
  createInMemoryRevocationStore,
  revocationRetainUntilSec,
  REVOCATION_RETAIN_SKEW_SEC,
  type RevocationStore,
  type RevocationList,
  type RevocationEntry,
  type RevokedSubject,
} from "./auth/revocation-store.js"
export {
  createCapCertRoleResolver,
  CapAuthError,
  type CapResolverOptions,
} from "./router/cap-resolver.js"
export {
  defaultServerPlugin,
  composePluginValidators,
  dispatchAfterWrite,
  type ServerPlugin,
  type CapCertValidator,
  type WriteEvent,
  type AfterWriteHook,
} from "./plugins.js"

// Errors
export { StartupError, AuthError, ConflictError, NotFoundError } from "./errors.js"

// Constants
export {
  ROLE_PUBLIC,
  ROLE_SELF,
  OP_READ,
  OP_WRITE,
  ENCRYPTION_NONE,
  ENCRYPTION_DELEGATED,
  ACTION_PULL,
  ACTION_PUSH,
  ACTION_LIST,
  IDENTITY_PARAM,
  IDENTITY_KEY,
  QUERY_CHECKPOINT,
  HKDF_INFO_DEFAULT,
  DEFAULT_CONFIG_KEY,
  ERROR_HASH_MISMATCH,
  CONTENT_TYPE_JSON,
} from "./constants.js"
