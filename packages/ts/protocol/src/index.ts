export { configurePlatform, getCrypto, getBase64 } from "./platform.js"
export type { CryptoProvider, Base64Provider, PlatformConfig } from "./platform.js"
export { stableStringify, computeHash } from "./hash.js"
export { buildRevocationList, revocationListCanonicalSigningInput } from "./revocation.js"
export type {
  RevocationList,
  RevocationEntry,
  RevokedSubject,
  BuildRevocationListOpts,
} from "./revocation.js"
export { deepMerge } from "./merge.js"
export { UNSAFE_KEYS, isUnsafeKey } from "./unsafe-keys.js"
export type { PullResult, PushSuccess, PullKeyringProjection, Timestamps } from "./types.js"
export { deriveKey, IV_BYTES, ENCRYPTED_KEY } from "./crypto.js"
export type { Encryptor } from "./crypto.js"
export {
  capCertCanonicalSigningInput,
  signCapCert,
  verifyCapCertSignature,
  assertCapCertWellFormed,
  verifyCapCert,
  pathGlobMatch,
  isRootDeviceCap,
  userIdFromPubHex,
} from "./cap.js"
export type {
  CapCert,
  CapKind,
  CapScope,
  UnsignedCapCert,
  CapCertVerifyResult,
  CapCertWellFormedCode,
  CapCertValidator,
  ServerPlugin,
  WriteEvent,
  AfterWriteHook,
  PullHookContext,
  PushHookContext,
  PullHookResult,
  PushHookResult,
  BeforePullHook,
  InterceptPushHook,
} from "./cap.js"
export type { AuditEntry, AuditLogger } from "./audit.js"
export {
  requestSigningCanonicalInput,
  signRequest,
  verifyRequestSignature,
  isWithinClockSkew,
} from "./request-signing.js"
export type {
  SignableMethod,
  SignableRequest,
  RequestSignature,
} from "./request-signing.js"
