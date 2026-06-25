// Config
export type {
  SyncConfig,
  CollectionConfig,
  NamespaceConfig,
  CollectionRateLimitConfig,
  RateLimitRule,
  RateLimitDimension,
  RateLimitConfig,
  EncryptionMode,
  FieldPermission,
  IdentityRestriction,
} from "./config/schema.js"
export { validateConfig, collectConfigWarnings } from "./config/validate.js"
export { parseConfigJson, loadConfig, saveConfig } from "./config/loader.js"

// Storage
export type { ObjectStore, StoreContext } from "./storage/base.js"
export { MemoryObjectStore, CustomObjectStore } from "./storage/memory.js"
export {
  type KVAdapter,
  type InMemoryKVAdapterOptions,
  createInMemoryKVAdapter,
} from "./storage/kv-adapter.js"
export {
  type K2VAdapterOptions,
  type K2VTransport,
  createK2VAdapter,
} from "./storage/k2v-adapter.js"

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
  resolveDocumentKey,
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
  checkRateLimiters,
  corsMiddleware,
  securityHeadersMiddleware,
  requestTimeoutMiddleware,
  type RateLimitBucketMode,
  type RateLimiterOptions,
  type CorsConfig,
  type SecurityHeadersConfig,
} from "./router/middleware.js"
export { matchesAllowedMime, isJsonCollection } from "./router/mime.js"

// Enrichers
export { composeEnrichers } from "./enrichers/compose.js"
export { makeIdentityRoleEnricher } from "./enrichers/identity.js"

// Events proxy (authenticated SSE)
export {
  createEventsProxyRouter,
  DEFAULT_SAFE_ID,
  type EventsProxyOptions,
} from "./events-proxy.js"

// Lifecycle
export { createGracefulShutdown, type GracefulShutdownOptions, type ShutdownHandle } from "./lifecycle.js"

// Logger
export { createConsoleLogger, createJsonLogger, createNoopLogger, type LogLevel, type LogEntry, type ServerLogger } from "./logger.js"

// TTL
export { isExpired } from "./ttl.js"

// OpenAPI
export { generateOpenApiSpec } from "./openapi.js"

// Parquet / DuckDB
export {
  createParquetCollection,
  duckdbReadParquetSql,
  type ParquetAccessMode,
  type ParquetCollectionOptions,
  type DuckdbParquetSqlOptions,
  type DuckdbParquetSqlResult,
  PARQUET_MIME_TYPE,
  PARQUET_MIME_TYPES,
} from "./parquet.js"

// Cap-cert auth (v3, opt-in)
export {
  createInMemoryNonceCache,
  createKvNonceCache,
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
  authenticateMetaRequest,
  CapAuthError,
  type CapResolverOptions,
  type MetaAuthOptions,
  type MetaRequestHeaders,
} from "./router/cap-resolver.js"
export {
  defaultServerPlugin,
  composePluginValidators,
  dispatchAfterWrite,
  dispatchAuthorize,
  hasAuthorizeHook,
  type ServerPlugin,
  type CapCertValidator,
  type WriteEvent,
  type AfterWriteHook,
  type AuthorizeContext,
  type AuthorizeResult,
  type AuthorizeHook,
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
