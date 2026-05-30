export { configurePlatform } from "@drakkar.software/starfish-protocol"
export type { CryptoProvider, Base64Provider, PlatformConfig } from "@drakkar.software/starfish-protocol"
export { stableStringify, computeHash } from "@drakkar.software/starfish-protocol"
export { buildRevocationList, revocationListCanonicalSigningInput } from "@drakkar.software/starfish-protocol"
export type {
  RevocationList,
  RevocationEntry,
  RevokedSubject,
  BuildRevocationListOpts,
} from "@drakkar.software/starfish-protocol"
export type { PullResult, PushSuccess, PullKeyringProjection } from "@drakkar.software/starfish-protocol"

export { StarfishClient, pullWasFromCache } from "./client.js"
export type {
  BlobPullResult,
  BlobPushResult,
  AppendPullOptions,
  PullOptions,
  BatchPullOptions,
  BatchPullResult,
  BatchPullEntry,
} from "./client.js"
export { SyncManager, AbortError } from "./sync.js"
export type { SyncManagerOptions, SyncSigner } from "./sync.js"
export { AppendLogCursor, AppendAuthorError, checkpointOf } from "./append-log.js"
export type { AppendLogCursorOptions, AppendElement, AuthorVerifier, ElementErrorPolicy } from "./append-log.js"
export { ENCRYPTED_KEY } from "@drakkar.software/starfish-protocol"
export type { Encryptor } from "@drakkar.software/starfish-protocol"
export {
  ConflictError,
  StarfishHttpError,
} from "./types.js"
export type {
  StarfishClientOptions,
  StarfishCapProvider,
  PullCache,
  ConflictResolver,
  ClientPlugin,
} from "./types.js"
export { consoleSyncLogger, noopSyncLogger, createMetricsCollector } from "./logger.js"
export type { SyncLogger, SyncMetrics, MetricsCollector } from "./logger.js"
export { createMigrator } from "./migrate.js"
export type { MigrationFn, MigrationConfig } from "./migrate.js"
export { ValidationError, createSchemaValidator } from "./validate.js"
export type { Validator, ValidationResult } from "./validate.js"
export { classifyError } from "./fetch.js"
export type { ErrorCategory } from "./fetch.js"
export {
  createUnionMerge,
  createSoftDeleteResolver,
  timestampWinner,
  pruneTombstones,
  withConflictMeta,
} from "./resolvers.js"
export type { ConflictMeta, ConflictResolverWithMeta } from "./resolvers.js"
export { SnapshotHistory } from "./history.js"
export type { Snapshot, SnapshotHistoryOptions } from "./history.js"
export { startPolling, startAdaptivePolling } from "./polling.js"
export type { PollableState, AdaptivePollingOptions, AdaptivePollingControls } from "./polling.js"
export { createDedupFetch } from "./dedup.js"
export { fetchServerConfig } from "./config.js"
export type { EncryptionMode, CollectionClientInfo, ConfigResponse } from "./config.js"
export { createIndexedDBStorage } from "./storage/indexeddb.js"
export type { IndexedDBStorageOptions, AsyncStateStorage } from "./storage/indexeddb.js"
export { exportData, importData, exportToBlob } from "./export.js"
export type { ExportOptions } from "./export.js"
export { isBackgroundSyncSupported, registerBackgroundSync } from "./background-sync.js"
export type { BackgroundSyncOptions } from "./background-sync.js"
export { isServiceWorkerSupported, registerServiceWorker, unregisterServiceWorkers } from "./service-worker.js"
export type { ServiceWorkerOptions } from "./service-worker.js"
export { createSuspenseResource } from "./bindings/suspense.js"
export { createDebouncedSync, createDebouncedPush } from "./debounced-sync.js"
export type { DebouncedSyncOptions, DebouncedSync, DebouncedPushOptions, DebouncedPush } from "./debounced-sync.js"
export { createMobileLifecycle, createAppendLogMobileLifecycle } from "./mobile-lifecycle.js"
export type { AppStateModule, NetInfoModule, MobileLifecycleDeps, MobileLifecycleOptions, AppendLogLifecycleOptions } from "./mobile-lifecycle.js"
export { createMultiStoreSync } from "./multi-store.js"
export type {
  StoreSlice,
  BackupDocument,
  MultiStoreMigrationFn,
  MultiStoreSyncOptions,
  MultiStoreSync,
} from "./multi-store.js"
export type { AppendOnlyClientInfo } from "./config.js"
