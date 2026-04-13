export { configurePlatform } from "@drakkar.software/starfish-protocol"
export type { CryptoProvider, Base64Provider, PlatformConfig } from "@drakkar.software/starfish-protocol"
export { stableStringify, computeHash } from "@drakkar.software/starfish-protocol"
export type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"

export { StarfishClient } from "./client.js"
export type { BlobPullResult, BlobPushResult } from "./client.js"
export { SyncManager } from "./sync.js"
export type { SyncManagerOptions } from "./sync.js"
export { createEncryptor, ENCRYPTED_KEY } from "./crypto.js"
export type { Encryptor } from "./crypto.js"
export {
  ConflictError,
  StarfishHttpError,
} from "./types.js"
export type {
  StarfishClientOptions,
  AuthProvider,
  ConflictResolver,
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
export { createMobileLifecycle } from "./mobile-lifecycle.js"
export type { AppStateModule, NetInfoModule, MobileLifecycleDeps, MobileLifecycleOptions } from "./mobile-lifecycle.js"
export { createMultiStoreSync } from "./multi-store.js"
export type {
  StoreSlice,
  BackupDocument,
  MultiStoreMigrationFn,
  MultiStoreSyncOptions,
  MultiStoreSync,
} from "./multi-store.js"
export {
  deriveGroupKeyPair,
  generateGroupKey,
  wrapGroupKey,
  unwrapGroupKey,
  createGroupKeyring,
  addGroupMember,
  rotateGroupKey,
  createGroupEncryptor,
} from "./group-crypto.js"
export type { GroupKeyPair, EpochKeyring, GroupKeyring } from "./group-crypto.js"
