export { configurePlatform, getCrypto, getBase64 } from "./platform.js"
export type { CryptoProvider, Base64Provider, PlatformConfig } from "./platform.js"
export * as ed25519Suite from "./suites/ed25519.js"
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
  recipientKem,
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
  AuthorizeContext,
  AuthorizeResult,
  AuthorizeHook,
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
export {
  APPEND_AUTHOR_DOMAIN,
  DOC_AUTHOR_DOMAIN,
  appendAuthorCanonicalInput,
  signAppendAuthor,
  verifyAppendAuthor,
  docAuthorCanonicalInput,
  signDocAuthor,
  verifyDocAuthor,
} from "./append-author.js"
export type { AppendAuthor } from "./append-author.js"
export {
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  DATA_FIELD,
  TS_FIELD,
  BASE_HASH_FIELD,
  PUSH_PATH_PREFIX,
  HEADER_AUTHORIZATION,
  HEADER_SIG,
  HEADER_TS,
  HEADER_NONCE,
  HEADER_PUB,
  HEADER_CONTENT_TYPE,
  HEADER_ACCEPT,
  CORS_ALLOW_HEADERS,
} from "./constants.js"
