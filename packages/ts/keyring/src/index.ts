/**
 * `@drakkar.software/starfish-keyring` — multi-recipient encryption layer.
 *
 * Public surface: keyring lifecycle (create/add/rotate), encryptor factory,
 * wrap/unwrap primitives, recipient management bound to a Starfish collection,
 * and the locked protocol constants.
 */

export {
  KEYRING_WRAP_SALT,
  KEYRING_WRAP_INFO,
  KEYRING_IV_BYTES,
  wrapForRecipient,
  unwrapFromEntry,
  verifyEntrySignature,
  createKeyring,
  addRecipient,
  rotateEpoch,
  createKeyringEncryptor,
} from "./keyring.js"
export type {
  WrappedKeyEntry,
  KeyringEpoch,
  Keyring,
  KeyringEncryptor,
} from "./keyring.js"

export {
  keyringPathFor,
  addRecipient as addCollectionRecipient,
  removeRecipient,
  listRecipients,
  currentEpoch,
} from "./recipients.js"
export type {
  RecipientRef,
  AdderKeys,
  RecipientMutationOpts,
  ListedRecipient,
} from "./recipients.js"

// Sealed envelopes — wrap a secret to a single static KEM key for carrying in a
// plaintext synced doc (sealed credentials, bearer secrets, peer hand-offs).
// `seal`/`sealToSelf` accept an optional `aad` (Additional Authenticated Data)
// string for context-binding; `unseal`/`unsealToString`/`unsealFromSelf` accept
// `opts.aad` to open `v:1` blobs sealed with a context string.
export {
  seal,
  sealToSelf,
  unseal,
  unsealToString,
  unsealFromSelf,
} from "./seal.js"
export type { SealedBlob, SealerKeys } from "./seal.js"

// Keyring lifecycle helper — idempotent ensure-and-add (create keyring on first
// use, skip duplicate, retry on CAS conflict).
export { ensureKeyringRecipient, keyringPathFor as ensureKeyringPath } from "./ensure.js"
export type { EnsureKeyringRecipientOptions } from "./ensure.js"

// Low-level crypto utilities shared with the identities extension (HKDF,
// hex codec, byte concat). Stable enough to expose for inter-extension use.
export { hkdfBytes, bytesToHex, hexToBytes, concat } from "./_crypto_helpers.js"
