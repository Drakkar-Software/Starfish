export type EncryptionMode = "none" | "delegated"

/** A single counted dimension of a two-independent rate-limit rule. `windowMs` /
 *  `maxRequests` inherit from the rule, then the flat collection fields, then the
 *  global `SyncConfig.rateLimit`, when omitted. */
export interface RateLimitDimension {
  windowMs?: number
  maxRequests?: number
}

/** A rate-limit rule for one collection action (push / pull / list).
 *
 *  Two shapes (mutually exclusive):
 *  - **Single counter** — `windowMs` / `maxRequests` with an optional `bucket` mode.
 *  - **Two independent limits** — `identity` and/or `ip` sub-limits, each its own
 *    counter; the request is rejected if EITHER dimension is over budget. Use this
 *    for "≤N per identity AND ≤M per ip". A rule using `identity`/`ip` must NOT also
 *    set `bucket` (rejected at config load).
 *
 *  `windowMs` / `maxRequests` inherit from the flat collection fields, then the
 *  global `SyncConfig.rateLimit`, when omitted. */
export interface RateLimitRule {
  windowMs?: number
  maxRequests?: number
  /** How requests are grouped into a single counter. `"identity"` (default) keys by
   *  the authenticated caller, falling back to X-Forwarded-For / client IP / a shared
   *  "anonymous" bucket. `"ip"` keys strictly by IP, ignoring identity. `"identity+ip"`
   *  keys by the (identity, ip) pair — one budget per distinct combination.
   *  CAVEAT (TypeScript/Hono): there is no portable socket IP, so `"ip"`/`"identity+ip"`
   *  key by the first `X-Forwarded-For` hop only; with no such header the ip part is the
   *  shared "anonymous" bucket. Put this server behind a proxy that sets `X-Forwarded-For`. */
  bucket?: "identity" | "ip" | "identity+ip"
  /** Two-independent form: per-identity dimension. Present ⇒ enforce a per-identity limit. */
  identity?: RateLimitDimension
  /** Two-independent form: per-ip dimension. Present ⇒ enforce a per-ip limit. */
  ip?: RateLimitDimension
}

export interface CollectionRateLimitConfig {
  /** Legacy flat fields. Treated as an implicit `push` rule (preserving the
   *  original push-only behavior) and as default `windowMs`/`maxRequests` for any
   *  explicit per-action rule that omits them. */
  windowMs?: number
  maxRequests?: number
  /** Bucket mode for the legacy/implicit push rule. Default `"identity"`. */
  bucket?: "identity" | "ip" | "identity+ip"
  /** Per-action overrides. Each action gets its own counter. An action with no
   *  rule (and, for push, no legacy flat fields) is unmetered. */
  push?: RateLimitRule
  pull?: RateLimitRule
  list?: RateLimitRule
}

export interface FieldPermission {
  readRoles?: string[]
  writeRoles?: string[]
}

/**
 * A static identity restriction rule. Declared in the JSON-serializable config
 * at the server (`SyncConfig`), namespace (`NamespaceConfig`), or collection
 * (`CollectionConfig`) level; the level it is attached to determines its scope.
 *
 * `mode: "deny"` blocks the listed identities; `mode: "allow"` permits ONLY the
 * listed identities (everyone else, including anonymous callers, is blocked).
 * When both kinds of rule apply to a request, **deny wins**.
 *
 * IMPORTANT: these rules carry NO behavior on their own — they are enforced
 * only when an `authorize`-hook plugin is installed that ingests them, namely
 * `createRestrictionsPlugin({ config })` from
 * `@drakkar.software/starfish-restrictions`. `createSyncRouter` logs a warning
 * if a config declares `restrictions` but no such plugin is wired.
 *
 * Callbacks cannot live in serializable config; for dynamic identity lists,
 * pass runtime rules to `createRestrictionsPlugin({ rules })` instead.
 */
export interface IdentityRestriction {
  /** `"deny"` blocks listed identities; `"allow"` permits only listed identities. */
  mode: "deny" | "allow"
  /** The identities this rule applies to. */
  identities: string[]
  /** Restrict the rule to these actions. Omit (or empty) = all actions. */
  actions?: ("pull" | "push" | "list")[]
}

/** Append-only strategy. Tagged by `type` so new strategies can be added later;
 *  only `"by_timestamp"` is supported today (each element is stored as `{ts, data}`
 *  and pulls filter by `ts` via `?checkpoint=`). */
export interface AppendOnlyConfig {
  /** Discriminator. Only `"by_timestamp"` is currently supported. */
  type: "by_timestamp"
  /** Array field name in the stored document. Defaults to "items". */
  field?: string
  /** true (default) — append the incoming item to the stored array as `{ts, data}`.
   *  false — compute a hash and emit a write event without writing to storage
   *  (consumed by a plugin such as starfish-queuing; replaces queueOnly). */
  persist?: boolean
  /** Opt-in cap: reject an append once the stored element count has reached this
   *  many, with `409 { error: "append_limit_exceeded", limit }`. Unset = unlimited.
   *  Bounds a single document; for higher volume, partition by a path parameter
   *  (e.g. `storagePath: "events/{date}"`). Requires `persist` (the default). */
  maxItems?: number
  /** Opt-in segmented storage: store the log as fixed-size sealed chunks of this
   *  many elements (plus a small head document) instead of one growing blob. Bounds
   *  append cost to O(chunkSize) (no O(n²) build) and lets `?checkpoint=`/`?last=`
   *  pulls read only the chunks they need. Unset = single-document (legacy) layout.
   *  Recommended ~10000. Server-internal only — the wire format is unchanged.
   *  Requires `persist` (the default). */
  chunkSize?: number
  /** Require a cryptographic author proof on every append (DEFAULT: `true`).
   *  When enforced, an append MUST carry `authorPubkey` + `authorSignature` (an
   *  Ed25519 signature over the element `data`, see
   *  `@drakkar.software/starfish-protocol` `signAppendAuthor`); the server
   *  verifies the signature and, when the auth layer identifies the caller (any
   *  cap-cert request), that `authorPubkey` equals the request presenter — so the
   *  stored author cannot be forged. The proof is stored on the element for
   *  readers to re-verify. Set `false` ONLY for an unauthenticated/public-write
   *  log where author identity is meaningless. */
  requireAuthorSignature?: boolean
  /** Allow `?full=true` pulls (DEFAULT: `true`). When `false`, a pull asking for
   *  the whole collection is rejected `400 { error: "full_not_allowed" }`,
   *  forcing every reader to bound its fetch with `?checkpoint=`/`?limit=`. */
  allowFull?: boolean
  /** Opt-in cap on the `?limit=`/`?last=` tail a pull may request. A larger value
   *  is silently clamped down to this. Unset = uncapped. Positive integer. */
  maxPullLimit?: number
  /** Opt-in bound (ms) on how far back a `?checkpoint=` may reach: a checkpoint
   *  older than `now - maxCheckpointAgeMs` is rejected
   *  `400 { error: "checkpoint_too_old" }`. Stops readers rewinding to ancient
   *  history. Unset = unbounded. Positive integer. */
  maxCheckpointAgeMs?: number
}

export interface CollectionConfig {
  name: string
  storagePath: string
  readRoles: string[]
  writeRoles: string[]
  encryption: EncryptionMode
  maxBodyBytes: number
  rateLimit?: CollectionRateLimitConfig | null
  cacheDurationMs?: number
  objectSchema?: Record<string, unknown>
  allowedMimeTypes: string[]
  pullOnly?: boolean
  pushOnly?: boolean
  forceFullFetch?: boolean
  bundle?: string
  /** When set, every push appends the incoming `data` as the last element of a stored array,
   *  recorded as `{ts, data}`. Pass `true` as shorthand for `{ type: "by_timestamp" }`. */
  appendOnly?: AppendOnlyConfig
  /** Document time-to-live in milliseconds. Expired documents return empty data on pull. */
  ttlMs?: number
  /** Per-field read/write permissions. Keys are top-level field names. */
  fieldPermissions?: Record<string, FieldPermission>
  /** Optional override for the keyring storage path. When omitted, defaults to
   *  `<storagePath>/_keyring`. Only relevant for `"delegated"` encryption. */
  keyringPath?: string
  /** When true, exposes a GET /list/... endpoint that returns the keys of existing documents
   *  under this collection's prefix. The last path parameter in storagePath is the one being
   *  enumerated. Requires at least one path parameter; incompatible with appendOnly and bundle. */
  listable?: boolean
  /** When true, only the **root device** (a self-signed device cap, `iss === sub`) may access
   *  this collection; every paired/delegated device cap and member cap is rejected with 403,
   *  in addition to the normal readRoles/writeRoles checks. Incompatible with public
   *  read/write roles (rejected at config load). */
  rootOnly?: boolean
  /** Static identity restrictions scoped to this collection. Enforced only when
   *  `createRestrictionsPlugin({ config })` (`@drakkar.software/starfish-restrictions`)
   *  is installed. See {@link IdentityRestriction}. */
  restrictions?: IdentityRestriction[]
}

export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
}

export interface NamespaceConfig {
  collections: CollectionConfig[]
  /** Static identity restrictions scoped to every collection in this namespace.
   *  Enforced only when `createRestrictionsPlugin({ config })`
   *  (`@drakkar.software/starfish-restrictions`) is installed. See
   *  {@link IdentityRestriction}. */
  restrictions?: IdentityRestriction[]
}

export interface SyncConfig {
  version: 1
  collections: CollectionConfig[]
  /**
   * Named sub-routers. Each key becomes a URL prefix: `/{name}/pull/...` and `/{name}/push/...`.
   * Keys must match `[a-zA-Z0-9_-]+` and must not be `pull`, `push`, `health`, or `batch`.
   * Each namespace must contain at least one collection.
   */
  namespaces?: Record<string, NamespaceConfig>
  rateLimit?: RateLimitConfig
  /** Static identity restrictions scoped to the entire server (every collection,
   *  in every namespace and the root). Enforced only when
   *  `createRestrictionsPlugin({ config })`
   *  (`@drakkar.software/starfish-restrictions`) is installed. See
   *  {@link IdentityRestriction}. */
  restrictions?: IdentityRestriction[]
}
