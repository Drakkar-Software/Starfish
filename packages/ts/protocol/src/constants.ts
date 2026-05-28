/**
 * Protocol wire-field-name constants.
 *
 * Field names that travel on the wire and are read/written by string key on
 * untyped JSON objects (request bodies, stored documents, pulled elements) are
 * defined here ONCE so the TypeScript and Python implementations cannot drift —
 * a typo or a one-sided rename is a compile/test failure, not a silent
 * interop break. Typed interfaces (e.g. {@link AppendAuthor}, `StoredDocument`)
 * keep these as declared property names — the compiler already pins those; this
 * module is for the places that index a `Record<string, unknown>` by string.
 *
 * Mirrored byte-for-byte by `starfish_protocol/constants.py`.
 */

// `as const` gives each constant its literal type, so a computed-key object
// `{ [AUTHOR_PUBKEY_FIELD]: x }` is typed `{ authorPubkey: x }` (not a widened
// `Record<string, …>`) — callers build typed `AppendAuthor`/`AppendElement`
// objects from the constants without re-declaring the key names.

/** Author proof attached to a signed append/push: the author's public key (hex). */
export const AUTHOR_PUBKEY_FIELD = "authorPubkey" as const

/** Author proof attached to a signed append/push: base64 signature over the data. */
export const AUTHOR_SIGNATURE_FIELD = "authorSignature" as const

/** Request-body field carrying the write payload (`{ data }` / `{ data, baseHash }`). */
export const DATA_FIELD = "data" as const

/** Request-body field carrying a client-supplied element/document timestamp (ms). */
export const TS_FIELD = "ts" as const

/** Request-body field carrying the optimistic-concurrency base hash (merge push). */
export const BASE_HASH_FIELD = "baseHash" as const

/** Action prefix on a push endpoint path. The storage `documentKey` is the push
 *  `path` with this prefix stripped (the namespace lives only in the URL), and the
 *  author signature binds to that `documentKey`. */
export const PUSH_PATH_PREFIX = "/push/"

// HTTP header names of the v3 request-auth contract. Defined here so the client
// (which sends them) and the server cap-resolver (which reads them) cannot drift.
/** `Authorization: Cap <base64(stableStringify(cap))>`. */
export const HEADER_AUTHORIZATION = "Authorization"
/** Base64 Ed25519 request signature. */
export const HEADER_SIG = "X-Starfish-Sig"
/** Request signature timestamp (ms). */
export const HEADER_TS = "X-Starfish-Ts"
/** Request signature nonce (base64). */
export const HEADER_NONCE = "X-Starfish-Nonce"
/** Presenter's Ed25519 public key (hex) — required for an audience-cap redemption. */
export const HEADER_PUB = "X-Starfish-Pub"
/** `Content-Type` header name. */
export const HEADER_CONTENT_TYPE = "Content-Type"
/** `Accept` header name. */
export const HEADER_ACCEPT = "Accept"
