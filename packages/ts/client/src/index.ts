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
export { consoleSyncLogger, noopSyncLogger } from "./logger.js"
export type { SyncLogger } from "./logger.js"
export { createMigrator } from "./migrate.js"
export type { MigrationFn, MigrationConfig } from "./migrate.js"
export { ValidationError, createSchemaValidator } from "./validate.js"
export type { Validator, ValidationResult } from "./validate.js"
