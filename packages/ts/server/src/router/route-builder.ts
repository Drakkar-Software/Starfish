import { Hono } from "hono"
import type { Context } from "hono"
import {
  getCrypto,
  computeHash,
  verifyAppendAuthor,
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  DATA_FIELD,
  TS_FIELD,
} from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { KVAdapter } from "../storage/kv-adapter.js"
import type {
  SyncConfig,
  CollectionConfig,
  CollectionRateLimitConfig,
  RateLimitRule,
  EncryptionMode,
  FieldPermission,
  NamespaceConfig,
  AppendOnlyConfig,
} from "../config/schema.js"
import { pull } from "../protocol/pull.js"
import {
  handleSyncPull,
  handleSyncPush,
  handleAppendOnlyPull,
  validatePathSegment,
  isUnsafeDocumentKey,
  deepSanitize,
  jsonDepthWithin,
  isWithKeyringEnabled,
  type AppendPullBounds,
} from "./helpers.js"
import { appendItem } from "../protocol/push.js"
import {
  checkBodyLimit,
  RateLimiter,
  checkRateLimiters,
  corsMiddleware,
  securityHeadersMiddleware,
  requestTimeoutMiddleware,
  type CorsConfig,
  type SecurityHeadersConfig,
} from "./middleware.js"
import { matchesAllowedMime, isJsonCollection } from "./mime.js"
import { matchScopePath } from "./cap-resolver.js"
import {
  ROLE_PUBLIC,
  ROLE_SELF,
  ROLE_ROOT_DEVICE,
  OP_READ,
  OP_WRITE,
  ENCRYPTION_DELEGATED,
  ACTION_PULL,
  ACTION_PUSH,
  ACTION_LIST,
  IDENTITY_PARAM,
  IDENTITY_KEY,
  QUERY_CHECKPOINT,
  QUERY_LIMIT,
  QUERY_LAST,
  QUERY_FULL,
  APPEND_DEFAULT_FIELD,
  APPEND_MAX_FUTURE_TS_SKEW_MS,
  ERROR_APPEND_PARAMS_NOT_SUPPORTED,
} from "../constants.js"
import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import { dispatchAfterWrite, dispatchBeforePull, dispatchInterceptPull, dispatchInterceptPush, dispatchAuthorize, hasAuthorizeHook } from "../plugins.js"
import type { ServerLogger } from "../logger.js"
import type { AuditLogger, AuditEntry } from "@drakkar.software/starfish-protocol"
import { isExpired } from "../ttl.js"

export interface AuthResult {
  identity: string
  roles: string[]
  /**
   * Expanded cap-cert scope paths (`{identity}` already substituted), or
   * undefined for resolvers that carry no path scope (e.g. pure role-based
   * auth). Used to authorize the sibling `_keyring` read of the
   * `?withKeyring=1` optimization.
   */
  scopePaths?: string[]
  /**
   * The verified request presenter — the public key that signed THIS request
   * (the cap subject for a device/member cap, the redeemer for an audience cap)
   * and its crypto suite. Set by the cap-cert resolver; `undefined` for a
   * resolver that carries no per-request key (pure role-based auth). Used to
   * bind a signed append's `authorPubkey` to its authenticated writer so the
   * stored author cannot be forged.
   */
  presenter?: { pubHex: string }
}

/**
 * Per-request stash of the caller's expanded cap scope, keyed by the Hono
 * context. Written once during auth resolution and read by the pull handler to
 * authorize the sibling `_keyring` read of the `?withKeyring=1` optimization.
 * A WeakMap avoids leaking framework-typed context variables and is GC'd with
 * the request.
 */
const scopePathsByContext = new WeakMap<Context, string[] | undefined>()

export type RoleResolver = (c: Context) => Promise<AuthResult>
/**
 * Derives extra roles from the authenticated `auth` and the request `params`
 * (e.g. team membership from `params.teamId`). MUST be idempotent and free of
 * observable side effects: it can be invoked MORE THAN ONCE per request — the
 * `/batch/pull` handler calls it once per requested collection (each with that
 * collection's params) off a single auth resolve. (The replay-protected
 * resolver runs once; the enricher does not consume the nonce.)
 */
export type RoleEnricher = (
  auth: AuthResult,
  params: Record<string, string>,
) => Promise<string[]>

/** Controls how the GET /config endpoint authenticates callers. */
export interface ConfigEndpointOptions {
  /** `"public"` — no auth, all collections returned.
   *  `"role-filtered"` — roleResolver runs; caller sees only collections
   *  whose readRoles or writeRoles intersect the caller's roles. */
  auth: "public" | "role-filtered"
}

/** Per-collection metadata returned by GET /config. */
export interface CollectionClientInfo {
  name: string
  maxBodyBytes: number
  encryption: EncryptionMode
  allowedMimeTypes: string[]
  pullOnly?: boolean
  pushOnly?: boolean
  appendOnly?: AppendOnlyConfig
  ttlMs?: number
  forceFullFetch?: boolean
}

/** Response shape of GET /config. */
export interface ConfigResponse {
  collections: CollectionClientInfo[]
  namespaces?: Record<string, { collections: CollectionClientInfo[] }>
}

export interface SyncRouterOptions {
  store: ObjectStore
  config: SyncConfig
  roleResolver: RoleResolver
  roleEnricher?: RoleEnricher
  /** Server plugins. `afterWrite` hooks fire after each successful push (e.g.
   *  `starfish-queuing`); `beforePull`/`interceptPush` hooks gate the pull/push
   *  routes (e.g. `starfish-replica` enforces write modes and proxies writes). */
  plugins?: ServerPlugin[]
  roleResolverTimeout?: number
  /** Enable CORS. Pass true for permissive defaults, or a CorsConfig for fine-grained control. */
  cors?: boolean | CorsConfig
  /** Enable security headers (X-Content-Type-Options, X-Frame-Options, HSTS, etc.).
   *  Defaults to false. Pass true for defaults, or a SecurityHeadersConfig to customise. */
  securityHeaders?: boolean | SecurityHeadersConfig
  /** Enable gzip response compression via CompressionStream. */
  compression?: boolean
  /** Per-request timeout in milliseconds. Requests exceeding this return 408. */
  requestTimeoutMs?: number
  /** Structured server logger. */
  logger?: ServerLogger
  /** Audit logger for recording access events. */
  auditLogger?: AuditLogger
  /** When set, exposes a GET /config endpoint returning per-collection client metadata.
   *  Omit to disable the endpoint entirely (default). */
  configEndpoint?: ConfigEndpointOptions
  /** Max collections a single `/batch/pull` request may name. Bounds the
   *  per-request work (store reads + enricher + scope checks) one signed request
   *  can drive, since the rate limiter caps requests, not work-per-request.
   *  Defaults to `DEFAULT_MAX_BATCH_COLLECTIONS` (100). */
  maxCollectionsPerBatch?: number
  /** Shared store for rate-limit counters. When omitted, each rate limiter uses its
   *  own in-memory (process-local) store — the original behavior. Pass a networked
   *  {@link KVAdapter} (e.g. Garage K2V) to enforce rate limits across server instances;
   *  counters are namespaced per collection/action/dimension automatically. */
  rateLimitStore?: KVAdapter
  /** Number of trusted reverse-proxy hops directly in front of this server, used by
   *  every rate limiter to locate the real client IP in `X-Forwarded-For`. Defaults
   *  to `0`: the client-controlled XFF header is NOT trusted for bucketing (a spoofed
   *  header cannot mint fresh buckets). Set it to the exact number of proxies you
   *  operate to enable secure per-client IP bucketing (`bucket: "ip"` / `"identity+ip"`
   *  / an `ip` sub-limit). See {@link RateLimiterOptions.trustedProxyHops}. */
  trustedProxyHops?: number
  /** Maximum total append elements across all entries in one batch pull request.
   * Guards against 100×maxPullLimit amplification. Default: 5000. */
  maxBatchAppendElements?: number
  /** Resolved batch keys ending in any of these suffixes are rejected Forbidden
   * regardless of the caller's roles. Defaults to ["_keyring","_members"] so a
   * misconfigured enricher-authorized route cannot expose sibling sensitive docs.
   * Pass `[]` to disable. */
  batchKeyDenySuffixes?: string[]
}

function toRoutePath(action: string, storagePath: string): string {
  // Convert {param} to :param for Hono routing
  const honoPath = storagePath.replace(/\{(\w+)\}/g, ":$1")
  return `/${action}/${honoPath}`
}

/** Derives the list route path by dropping the last path segment (the enumerated param). */
function toListRoutePath(storagePath: string): string {
  const segments = storagePath.split("/")
  const prefixPath = segments.slice(0, -1).join("/")
  return toRoutePath(ACTION_LIST, prefixPath)
}

/** Derives the storage key prefix for listKeys from a storagePath with the last param removed. */
function toListPrefix(storagePath: string, params: Record<string, string>): string {
  const segments = storagePath.split("/")
  const prefixTemplate = segments.slice(0, -1).join("/")
  const resolved = resolveDocumentKey(prefixTemplate, params)
  return resolved ? resolved + "/" : ""
}

const LIST_DEFAULT_LIMIT = 100
const LIST_MAX_LIMIT = 1000

/** Build a binary pull HTTP response (Parquet / blob collections). */
async function binaryPullResponse(
  c: Context,
  body: Uint8Array,
  contentType: string,
  cacheDurationMs: number | undefined,
  isPublicRead: boolean,
): Promise<Response> {
  const headers = new Headers()
  headers.set("Content-Type", contentType)

  const cr = getCrypto()
  const hashBuf = await cr.subtle.digest("SHA-256", body.buffer as ArrayBuffer)
  const etag = Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
  headers.set("ETag", `"${etag}"`)

  const ifNoneMatch = c.req.header("if-none-match")
  if (ifNoneMatch === `"${etag}"`) {
    return new Response(null, { status: 304 })
  }

  if (cacheDurationMs != null) {
    const maxAge = Math.floor(cacheDurationMs / 1000)
    const directive = isPublicRead ? `max-age=${maxAge}` : `private, max-age=${maxAge}`
    headers.set("Cache-Control", directive)
  }

  return new Response(body.buffer as ArrayBuffer, { status: 200, headers })
}

/** Default cap on collections per `/batch/pull` request (see `maxCollectionsPerBatch`). */
const DEFAULT_MAX_BATCH_COLLECTIONS = 100

/** Resolves `{param}` placeholders in a `storagePath` template.
 *  The result is the S3 object key for binary collections and the
 *  document key for JSON collections.
 *
 * @example
 * resolveDocumentKey("datasets/{owner}/{dataset}", { owner: "alice", dataset: "sales.parquet" })
 * // → "datasets/alice/sales.parquet"
 */
export function resolveDocumentKey(
  template: string,
  params: Record<string, string>,
): string {
  let result = template
  for (const [key, value] of Object.entries(params)) {
    result = result.replaceAll(`{${key}}`, value)
  }
  return result
}

function extractPathParams(
  storagePath: string,
  params: Record<string, string>,
): Record<string, string> {
  // Hono already extracts params for us via :param syntax
  // Map them back to the original {param} template names
  const templateParams = storagePath.match(/\{(\w+)\}/g)
  if (!templateParams) return {}
  const result: Record<string, string> = {}
  for (const tp of templateParams) {
    const name = tp.slice(1, -1)
    if (params[name] != null) {
      result[name] = params[name]!
    }
  }
  return result
}

function validateAllParams(params: Record<string, string>): boolean {
  for (const value of Object.values(params)) {
    if (!validatePathSegment(value)) return false
  }
  return true
}

/**
 * Strip fields the caller's roles cannot read from a pulled `data` object,
 * in place. Shared by the standalone, bundle, and batch pull paths so field-
 * read permissions are enforced identically everywhere (the bundle and batch
 * paths previously skipped this, leaking restricted fields).
 */
function applyFieldReadFilter(
  data: unknown,
  fieldPermissions: CollectionConfig["fieldPermissions"],
  roles: Iterable<string>,
  appendField?: string,
): void {
  if (!fieldPermissions || data == null || typeof data !== "object") return
  const userRoles = new Set(roles)
  const obj = data as Record<string, unknown>
  for (const [field, perm] of Object.entries(fieldPermissions)) {
    if (perm.readRoles && perm.readRoles.length > 0) {
      const hasAccess = perm.readRoles.some((r) => userRoles.has(r) || r === ROLE_PUBLIC)
      if (!hasAccess) delete obj[field]
    }
  }
  // If this is an append-only result, also strip restricted fields from each
  // element's nested .data object (elements are {ts, data:{...}}).
  if (appendField != null && Array.isArray(obj[appendField])) {
    for (const element of obj[appendField] as Array<{ data?: Record<string, unknown> }>) {
      if (element != null && typeof element.data === "object" && element.data != null) {
        applyFieldReadFilter(element.data as Record<string, unknown>, fieldPermissions, userRoles)
      }
    }
  }
}

/**
 * Run the role resolver ONCE and return the raw `AuthResult` plus the caller's
 * base roles, WITHOUT folding in the per-collection `self`/enricher roles. The
 * resolver consumes the request nonce (replay protection), so it must run at
 * most once per request: a handler that authorizes many collections (bundle
 * pull, batch pull) calls this once, then `foldCollectionRoles` per collection.
 * Stashes the cap scope (if any) for sibling-read authorization downstream.
 */
async function resolveBaseAuth(
  c: Context,
  opts: SyncRouterOptions,
): Promise<{
  auth: AuthResult | null
  identity: string | null
  baseRoles: Set<string>
  error: Response | null
  presenter?: { pubHex: string }
}> {
  let auth: AuthResult
  try {
    const timeout = opts.roleResolverTimeout ?? 5000
    auth = await Promise.race([
      opts.roleResolver(c),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeout),
      ),
    ])
  } catch (e) {
    if (e instanceof Error && e.message === "timeout") {
      return { auth: null, identity: null, baseRoles: new Set(), error: c.json({ error: "Unauthorized" }, 503) }
    }
    const status = (e as { status?: unknown })?.status
    if (status === 403) {
      return { auth: null, identity: null, baseRoles: new Set(), error: c.json({ error: "Forbidden" }, 403) }
    }
    if (status === 413) {
      const message = (e instanceof Error && e.message) || "Payload too large"
      return { auth: null, identity: null, baseRoles: new Set(), error: c.json({ error: message }, 413) }
    }
    console.error("[Starfish] roleResolver failed:", e)
    return { auth: null, identity: null, baseRoles: new Set(), error: c.json({ error: "Unauthorized" }, 401) }
  }

  // Stash the cap scope (if any) for sibling-read authorization downstream
  // (e.g. the ?withKeyring=1 keyring shortcut in the pull handler). undefined
  // for role-based resolvers that carry no path scope.
  scopePathsByContext.set(c, auth.scopePaths)

  return { auth, identity: auth.identity, baseRoles: new Set(auth.roles), error: null, presenter: auth.presenter }
}

/**
 * Fold the conditional `self` role and any enricher roles into a COPY of the
 * caller's base roles, for ONE collection's params + storagePath. Does NOT
 * re-run the resolver (so it never re-consumes the nonce) — a multi-collection
 * handler calls this once per collection with that collection's resolved params.
 */
async function foldCollectionRoles(
  auth: AuthResult,
  baseRoles: Set<string>,
  params: Record<string, string>,
  storagePath: string,
  opts: SyncRouterOptions,
  c: Context,
): Promise<{ roles: Set<string>; error: Response | null }> {
  const effectiveRoles = new Set(baseRoles)
  if (storagePath.includes(IDENTITY_PARAM)) {
    if (params[IDENTITY_KEY] === auth.identity) {
      effectiveRoles.add(ROLE_SELF)
    }
  }
  if (opts.roleEnricher) {
    try {
      const extra = await opts.roleEnricher(auth, params)
      for (const r of extra) effectiveRoles.add(r)
    } catch (e) {
      console.error("[Starfish] roleEnricher failed:", e)
      return { roles: effectiveRoles, error: c.json({ error: "Authorization error" }, 500) }
    }
  }
  return { roles: effectiveRoles, error: null }
}

/**
 * Run the role resolver ONCE and fold in the conditional `self` role and any
 * enricher roles. Returns the effective role set without checking it against a
 * specific collection — callers do that themselves. Thin wrapper over
 * `resolveBaseAuth` + `foldCollectionRoles` for the standalone and bundle pull
 * paths (one params set); batch pull calls the two halves directly so it can
 * fold per-collection params after a single resolve.
 */
async function resolveEffectiveRoles(
  c: Context,
  params: Record<string, string>,
  opts: SyncRouterOptions,
  storagePath: string,
): Promise<{
  identity: string | null
  roles: Set<string>
  error: Response | null
  presenter?: { pubHex: string }
}> {
  const base = await resolveBaseAuth(c, opts)
  if (base.error || base.auth == null) {
    return { identity: base.identity, roles: base.baseRoles, error: base.error, presenter: base.presenter }
  }
  const folded = await foldCollectionRoles(base.auth, base.baseRoles, params, storagePath, opts, c)
  return { identity: base.identity, roles: folded.roles, error: folded.error, presenter: base.presenter }
}

/**
 * The per-collection access decision shared by every authorized path
 * (`checkAuth`, the bundle-pull handler). Centralizing it keeps `rootOnly` and
 * the readRoles/writeRoles + public rules from drifting between call sites — a
 * divergence would let one route enforce a rule another silently skips.
 *
 * `rootOnly` is an additive gate: the caller must hold `ROLE_ROOT_DEVICE` (a
 * self-signed device cap) on top of the normal role check. Config validation
 * forbids `rootOnly` + public, so a rootOnly collection never short-circuits on
 * `ROLE_PUBLIC` here.
 */
function isAccessAllowed(
  col: CollectionConfig,
  operation: string,
  effectiveRoles: Set<string>,
): boolean {
  if (col.rootOnly && !effectiveRoles.has(ROLE_ROOT_DEVICE)) return false
  const requiredRoles = operation === OP_READ ? col.readRoles : col.writeRoles
  if (requiredRoles.includes(ROLE_PUBLIC)) return true
  return requiredRoles.some((r) => effectiveRoles.has(r))
}

async function checkAuth(
  col: CollectionConfig,
  operation: string,
  c: Context,
  params: Record<string, string>,
  opts: SyncRouterOptions,
  action: "pull" | "push" | "list",
  namespaceName?: string,
): Promise<{
  identity: string | null
  roles: string[]
  error: Response | null
  presenter?: { pubHex: string }
}> {
  const requiredRoles = operation === OP_READ ? col.readRoles : col.writeRoles

  // A rootOnly collection is never public (enforced at config load), so it must
  // always resolve the caller's roles rather than short-circuit anonymous here.
  // When an authorize hook is installed (e.g. starfish-restrictions), the public
  // fast-path is also skipped so identity is resolved and an identity-based
  // restriction can apply even to a public collection.
  if (!col.rootOnly && requiredRoles.includes(ROLE_PUBLIC) && !hasAuthorizeHook(opts.plugins)) {
    return { identity: null, roles: [], error: null }
  }

  // Record auth-layer denials (401/403/…) so the trail is not blind to them —
  // otherwise only requests that reach the handler are ever logged.
  const auditDenial = async (ident: string | null, err: Response): Promise<void> => {
    // Awaited so an async audit logger's write completes before we respond, and a
    // rejecting logger surfaces rather than becoming an unhandled rejection.
    await opts.auditLogger?.record({
      timestamp: Date.now(),
      action: operation === OP_READ ? "pull" : "push",
      collection: col.name,
      identity: ident,
      documentKey: "",
      success: false,
      statusCode: err.status,
      params,
    })
  }

  const { identity, roles, error, presenter } = await resolveEffectiveRoles(c, params, opts, col.storagePath)
  if (error) {
    await auditDenial(identity, error)
    return { identity, roles: [...roles], error, presenter }
  }

  const effectiveRolesArray = [...roles]
  if (!isAccessAllowed(col, operation, roles)) {
    const err = c.json({ error: "Forbidden" }, 403)
    await auditDenial(identity, err)
    return { identity, roles: effectiveRolesArray, error: err, presenter }
  }

  // Identity restrictions (e.g. starfish-restrictions): deny by identity
  // independent of roles. Runs for every action after the role check passes.
  const authz = await dispatchAuthorize(opts.plugins, {
    ...(identity != null && identity !== "" && { identity }),
    action,
    collection: col.name,
    ...(namespaceName != null && { namespace: namespaceName }),
    params,
    roles: effectiveRolesArray,
  })
  if (authz.action === "reject") {
    const err = c.json({ error: authz.error }, authz.status as any)
    await auditDenial(identity, err)
    return { identity, roles: effectiveRolesArray, error: err, presenter }
  }

  return { identity, roles: effectiveRolesArray, error: null, presenter }
}

/** Per-action rate limiters for one collection. Each action maps to a list of
 *  `RateLimiter`s — one for a single-counter rule, or up to two for a two-independent
 *  (per-identity AND per-ip) rule. A request is rejected if any limiter in the list
 *  trips. Unmetered actions are absent or map to an empty list. */
interface ActionRateLimiters {
  push?: RateLimiter[]
  pull?: RateLimiter[]
  list?: RateLimiter[]
}

const RATE_ACTIONS = ["push", "pull", "list"] as const

/** Resolve windowMs/maxRequests for one (sub-)limit: dim → rule → flat → global. */
function resolveWindowMax(
  dim: { windowMs?: number; maxRequests?: number } | undefined,
  rule: RateLimitRule,
  colRl: CollectionRateLimitConfig,
  globalRl: { windowMs: number; maxRequests: number } | undefined,
): { windowMs: number; maxRequests: number } | null {
  const windowMs = dim?.windowMs ?? rule.windowMs ?? colRl.windowMs ?? globalRl?.windowMs
  const maxRequests = dim?.maxRequests ?? rule.maxRequests ?? colRl.maxRequests ?? globalRl?.maxRequests
  if (windowMs == null || maxRequests == null) return null
  return { windowMs, maxRequests }
}

/** Build the list of limiters for one rule (single-counter, or two-independent).
 *  `kv` (when present) is the shared counter store; `keyBase` namespaces this rule's
 *  counters so distinct limiters sharing one store don't collide. */
function buildRuleLimiters(
  rule: RateLimitRule,
  colRl: CollectionRateLimitConfig,
  globalRl: { windowMs: number; maxRequests: number } | undefined,
  kv: KVAdapter | undefined,
  keyBase: string,
  trustedProxyHops: number,
): RateLimiter[] {
  // Two-independent form: a per-identity and/or per-ip dimension, each its own counter.
  if (rule.identity != null || rule.ip != null) {
    const limiters: RateLimiter[] = []
    if (rule.identity != null) {
      const r = resolveWindowMax(rule.identity, rule, colRl, globalRl)
      if (r) limiters.push(new RateLimiter(r.windowMs, r.maxRequests, undefined, "identity", { kv, keyPrefix: `${keyBase}i:`, trustedProxyHops }))
    }
    if (rule.ip != null) {
      const r = resolveWindowMax(rule.ip, rule, colRl, globalRl)
      if (r) limiters.push(new RateLimiter(r.windowMs, r.maxRequests, undefined, "ip", { kv, keyPrefix: `${keyBase}p:`, trustedProxyHops }))
    }
    return limiters
  }
  // Single-counter form.
  const r = resolveWindowMax(undefined, rule, colRl, globalRl)
  return r ? [new RateLimiter(r.windowMs, r.maxRequests, undefined, rule.bucket ?? "identity", { kv, keyPrefix: `${keyBase}s:`, trustedProxyHops })] : []
}

/**
 * Resolve per-action rate limiters from a collection's `rateLimit` config.
 *
 * Resolution per action: an explicit `push`/`pull`/`list` rule wins; otherwise, for
 * `push` only, a non-null `rateLimit` is treated as an implicit push rule (preserving
 * the original push-only behavior, which was gated on a global `rateLimit` also being
 * set). Each rule yields a single-counter limiter or a two-independent (identity+ip)
 * pair. An action whose limit cannot be fully resolved is left unmetered (explicit rules
 * that fail to resolve are rejected at config load).
 *
 * `keyScope` uniquely identifies this collection (incl. namespace) so that, when a shared
 * `rateLimitStore` is configured, counters are namespaced per collection/action/dimension.
 */
function buildActionRateLimiters(
  colRl: CollectionRateLimitConfig | null | undefined,
  opts: SyncRouterOptions,
  keyScope: string,
): ActionRateLimiters {
  const result: ActionRateLimiters = {}
  if (colRl == null) return result
  const globalRl = opts.config.rateLimit
  const kv = opts.rateLimitStore

  for (const action of RATE_ACTIONS) {
    let rule: RateLimitRule | undefined = colRl[action]
    // Legacy/implicit push rule: any non-null `rateLimit` opts push into limiting,
    // but only when a global `rateLimit` is also configured (the original gate).
    if (action === "push" && rule == null && globalRl != null) {
      rule = { windowMs: colRl.windowMs, maxRequests: colRl.maxRequests, bucket: colRl.bucket }
    }
    if (rule == null) continue
    const limiters = buildRuleLimiters(rule, colRl, globalRl, kv, `${keyScope}:${action}:`, opts.trustedProxyHops ?? 0)
    if (limiters.length > 0) result[action] = limiters
  }
  return result
}

/**
 * Build a `WriteEvent` from a successful push response and dispatch it to every
 * registered plugin's `afterWrite` hook. No-op when there are no plugins or the
 * push did not return 200. Plugin failures are logged, never propagated.
 */
async function emitWriteEvent(
  opts: SyncRouterOptions,
  col: CollectionConfig,
  response: Response,
  params: Record<string, string>,
  identity: string | null,
  bodyData?: Record<string, unknown>,
  namespaceName?: string,
): Promise<void> {
  if (!opts.plugins || opts.plugins.length === 0 || response.status !== 200) return
  let respBody: Record<string, unknown>
  try {
    respBody = (await response.clone().json()) as Record<string, unknown>
  } catch (e) {
    console.error("[Starfish] Failed to parse push response for write event:", e)
    return
  }
  const event: WriteEvent = {
    collection: col.name,
    hash: (respBody["hash"] as string) ?? "",
    timestamp: (respBody["timestamp"] as number) ?? 0,
    params,
    ...(bodyData !== undefined && { body: bodyData }),
    ...(namespaceName != null && { namespace: namespaceName }),
    ...(identity != null && identity !== "" && { identity }),
  }
  await dispatchAfterWrite(opts.plugins, event)
}

async function runPush(
  c: Context,
  col: CollectionConfig,
  params: Record<string, string>,
  documentKey: string,
  identity: string | null,
  rateLimiters: readonly RateLimiter[],
  opts: SyncRouterOptions,
  context?: StoreContext,
  presenter?: { pubHex: string },
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  // Hono has no portable socket IP; pass clientIp=null (direct anonymous traffic
  // shares one bucket). A proxy MUST set X-Forwarded-For for per-client limiting.
  const rateErr = await checkRateLimiters(rateLimiters, identity ?? null, c.req.header("x-forwarded-for") ?? null)
  if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)

  const contentType = c.req.header("content-type") ?? ""
  if (!contentType.includes("application/json")) {
    return c.json({ error: "Content-Type must be application/json" }, 415)
  }

  let body: unknown
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: "Body must be a JSON object" }, 400)
  }
  if (typeof body !== "object" || body == null || Array.isArray(body)) {
    return c.json({ error: "Body must be a JSON object" }, 400)
  }
  // Enforce a hard nesting bound (iteratively, so the check itself can't overflow)
  // before the recursive `deepSanitize` walks the structure — a deeply-nested body
  // would otherwise blow the call stack with a `RangeError`.
  if (!jsonDepthWithin(body)) {
    return c.json({ error: "Body nesting too deep" }, 400)
  }

  const bodyObj = body as Record<string, unknown>

  // Field-level write permissions: reject writes to restricted fields. Lives
  // here (not in the route handler) so BOTH the standalone and bundle push
  // paths enforce it — the bundle path calls runPush directly.
  if (col.fieldPermissions && isJsonCollection(col.allowedMimeTypes)) {
    const pushData = bodyObj[DATA_FIELD]
    if (pushData != null && typeof pushData === "object" && !Array.isArray(pushData)) {
      const userRoles = new Set(context?.roles ?? [])
      for (const [field, perm] of Object.entries(col.fieldPermissions)) {
        if (
          perm.writeRoles &&
          perm.writeRoles.length > 0 &&
          field in (pushData as Record<string, unknown>)
        ) {
          const hasAccess = perm.writeRoles.some((r) => userRoles.has(r) || r === ROLE_PUBLIC)
          if (!hasAccess) {
            return c.json({ error: `Field '${field}' is not writable with your roles` }, 403)
          }
        }
      }
    }
  }

  // JSON Schema validation
  if (col.objectSchema != null) {
    const data = bodyObj[DATA_FIELD]
    if (data != null && typeof data === "object" && !Array.isArray(data)) {
      const schemaErr = validateObjectSchema(data as Record<string, unknown>, col.objectSchema)
      if (schemaErr) return c.json(schemaErr.body, schemaErr.status as any)
    }
  }

  const store = opts.store
  const isClientEncrypted = col.encryption === ENCRYPTION_DELEGATED

  if (col.appendOnly) {
    const appendCfg = col.appendOnly
    const appendField = appendCfg.field ?? APPEND_DEFAULT_FIELD

    // The element payload. Opaque to the server: plaintext under "none", an
    // encryptor wrapper under "delegated" (both are JSON objects).
    const item = bodyObj[DATA_FIELD]
    if (item == null || typeof item !== "object" || Array.isArray(item)) {
      return c.json({ error: "Missing or invalid data" }, 400)
    }
    const sanitizedItem = deepSanitize(item as Record<string, unknown>)

    // Append author proof. The signature is over the SANITIZED item — the exact
    // bytes stored — so a reader who pulls the element re-verifies the same data.
    // When `requireAuthorSignature` is enforced (the default), a missing,
    // invalid, or forged proof is rejected here; the fields are then stored on
    // the element. An opt-out collection (`requireAuthorSignature: false`) skips
    // the check but still stores any proof the client sent.
    const authorPubkey =
      typeof bodyObj[AUTHOR_PUBKEY_FIELD] === "string"
        ? (bodyObj[AUTHOR_PUBKEY_FIELD] as string)
        : undefined
    const authorSignature =
      typeof bodyObj[AUTHOR_SIGNATURE_FIELD] === "string"
        ? (bodyObj[AUTHOR_SIGNATURE_FIELD] as string)
        : undefined
    if (appendCfg.requireAuthorSignature !== false) {
      if (authorPubkey === undefined || authorSignature === undefined) {
        return c.json({ error: "append requires authorPubkey and authorSignature" }, 400)
      }
      // Bind the author to the authenticated caller: the signing key MUST be the
      // request presenter (cap subject / audience redeemer). A pure role resolver
      // carries no presenter — the signature is still required and verified, but
      // cannot be bound to a caller identity (see append-only-collections docs).
      if (presenter && authorPubkey !== presenter.pubHex) {
        return c.json({ error: "append author must be the request presenter" }, 403)
      }
      // Bound to `documentKey` so a signed element cannot be replayed under a
      // different document key (see appendAuthorCanonicalInput).
      if (!verifyAppendAuthor(documentKey, sanitizedItem, authorPubkey, authorSignature)) {
        return c.json({ error: "invalid append author signature" }, 403)
      }
    }
    const author =
      authorPubkey !== undefined && authorSignature !== undefined
        ? { authorPubkey, authorSignature }
        : undefined

    // Optional client-supplied element timestamp (ms since epoch). When present
    // it must be a non-negative integer and strictly greater than the latest
    // stored element's ts (enforced in appendItem); otherwise the server assigns one.
    let providedTs: number | undefined
    const rawTs = bodyObj[TS_FIELD]
    if (rawTs !== undefined && rawTs !== null) {
      if (typeof rawTs !== "number" || !Number.isInteger(rawTs) || rawTs < 0) {
        return c.json({ error: "ts must be a non-negative integer" }, 400)
      }
      if (rawTs > Date.now() + APPEND_MAX_FUTURE_TS_SKEW_MS) {
        // Reject far-future timestamps so a writer can't poison the monotonic
        // counter and detach the log from wall-clock (breaking time checkpoints).
        return c.json({ error: "ts is too far in the future" }, 400)
      }
      providedTs = rawTs
    }

    if (appendCfg.persist === false) {
      // queue-only path: no storage write. Resolve the element ts and return its
      // hash; the write event is emitted by the outer push handler.
      const ts = providedTs ?? Date.now()
      const hash = await computeHash(sanitizedItem)
      return c.json({ hash, timestamp: ts }, 200)
    }

    // persist=true (default): append the element under the per-key write lock.
    // No hash/conflict check — an authorized append is always accepted (content-wise).
    // `maxItems`/`chunkSize` (opt-in) cap the log / select segmented storage.
    const outcome = await appendItem(
      store,
      documentKey,
      sanitizedItem,
      appendField,
      providedTs,
      { maxItems: appendCfg.maxItems, chunkSize: appendCfg.chunkSize, author },
      context,
    )
    if ("error" in outcome) {
      if ("limit" in outcome) {
        // The cap is configuration, not data — safe to echo the limit.
        return c.json({ error: outcome.error, limit: outcome.limit }, 409)
      }
      // Don't echo `latest` — it would leak the most-recent element's timestamp
      // to a write-only credential that has no read access to the log.
      return c.json({ error: outcome.error }, 409)
    }
    return c.json({ hash: outcome.hash, timestamp: outcome.timestamp }, 200)
  }

  const result = await handleSyncPush(
    documentKey,
    store,
    bodyObj,
    identity,
    isClientEncrypted,
    false,
    context,
    presenter,
  )
  return c.json(result.body, result.status as any)
}

async function runBinaryPush(
  c: Context,
  col: CollectionConfig,
  documentKey: string,
  identity: string | null,
  rateLimiters: readonly RateLimiter[],
  opts: SyncRouterOptions,
  context?: StoreContext,
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  // Hono has no portable socket IP; pass clientIp=null (direct anonymous traffic
  // shares one bucket). A proxy MUST set X-Forwarded-For for per-client limiting.
  const rateErr = await checkRateLimiters(rateLimiters, identity ?? null, c.req.header("x-forwarded-for") ?? null)
  if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)

  const contentType = c.req.header("content-type") ?? ""
  if (!matchesAllowedMime(contentType, col.allowedMimeTypes)) {
    return c.json(
      {
        error: `Content-Type '${contentType}' is not allowed. Allowed: ${JSON.stringify(col.allowedMimeTypes)}`,
      },
      415,
    )
  }

  const rawBuffer = await c.req.arrayBuffer()
  const body = new Uint8Array(rawBuffer)

  // SHA256 hash of the raw bytes
  const _crypto = getCrypto()
  const hashBuffer = await _crypto.subtle.digest("SHA-256", rawBuffer)
  const hashArray = new Uint8Array(hashBuffer)
  const contentHash = Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")

  const mediaType = contentType.split(";")[0]!.trim()
  if (!opts.store.putBytes) {
    return c.json({ error: "Store does not support binary operations" }, 501)
  }
  await opts.store.putBytes(documentKey, new Uint8Array(rawBuffer), { contentType: mediaType }, context)

  return c.json({ hash: contentHash })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let _ajvInstance: any = null
let _ajvLoadWarned = false

function validateObjectSchema(
  data: Record<string, unknown>,
  schema: Record<string, unknown>,
): { body: Record<string, unknown>; status: number } | null {
  if (!_ajvInstance) {
    // Try to load ajv dynamically
    try {
      const _require = typeof globalThis.require === "function" ? globalThis.require : undefined
      if (!_require) {
        if (!_ajvLoadWarned) {
          _ajvLoadWarned = true
          console.error(
            "[Starfish] objectSchema is configured but ajv is not available " +
            "(no require() in this runtime). Install ajv or call setAjv() to provide " +
            "an instance. Failing the write CLOSED — the schema cannot be validated.",
          )
        }
        // Fail CLOSED: a collection declares objectSchema but no validator can be
        // resolved. Rejecting the write is safer than silently skipping validation.
        return {
          body: { error: "Schema validation unavailable: no JSON Schema validator (install ajv or call setAjv)" },
          status: 500,
        }
      }
      const AjvModule = _require("ajv")
      const Ajv = AjvModule.default || AjvModule
      _ajvInstance = new Ajv()
    } catch (e) {
      if (!_ajvLoadWarned) {
        _ajvLoadWarned = true
        console.error(
          "[Starfish] objectSchema is configured but ajv failed to load. " +
          "Install ajv or call setAjv() to provide an instance. Failing the write " +
          "CLOSED — the schema cannot be validated.",
          e,
        )
      }
      // Fail CLOSED (see above): do not let an unvalidated write proceed.
      return {
        body: { error: "Schema validation unavailable: no JSON Schema validator (install ajv or call setAjv)" },
        status: 500,
      }
    }
  }
  try {
    const validate = _ajvInstance.compile(schema)
    const valid = validate(data)
    if (!valid && validate.errors && validate.errors.length > 0) {
      const err = validate.errors[0]
      return {
        body: {
          error: `Schema validation failed: ${err.message}`,
          path: err.instancePath ? err.instancePath.split("/").filter(Boolean) : [],
          validator: err.keyword,
        },
        status: 400,
      }
    }
  } catch (e) {
    console.error("[Starfish] Schema compilation/validation error (schema may be invalid):", e)
    return {
      body: { error: "Internal schema validation error" },
      status: 500,
    }
  }
  return null
}

// Allow injecting ajv instance for environments without require()
export function setAjv(ajv: unknown): void {
  _ajvInstance = ajv
}

function addCollectionRoutes(
  app: Hono,
  col: CollectionConfig,
  opts: SyncRouterOptions,
  namespaceName?: string,
): void {
  // Per-action rate limiters, built once and shared across this collection's
  // pull / list / push handler closures (each action has its own counter).
  const limiters = buildActionRateLimiters(col.rateLimit, opts, `${namespaceName ?? ""}/${col.name}`)

  if (!col.pushOnly) {
    const pullPath = toRoutePath(ACTION_PULL, col.storagePath)

    app.get(pullPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(col.storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error } = await checkAuth(col, OP_READ, c, params, opts, ACTION_PULL, namespaceName)
      if (error) return error

      if (limiters.pull) {
        const rateErr = await checkRateLimiters(limiters.pull, identity ?? null, c.req.header("x-forwarded-for") ?? null)
        if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)
      }

      const pullCtx: StoreContext = {
        collection: col.name,
        params,
        identity,
        roles,
        action: ACTION_PULL,
        ...(namespaceName != null && { namespace: namespaceName }),
      }

      // Pull-gating plugins (e.g. starfish-replica): reject write-only
      // collections, or sync from a primary before the local read.
      if (opts.plugins?.some((p) => p.beforePull)) {
        const decision = await dispatchBeforePull(opts.plugins, {
          collection: col.name,
          params,
          ...(namespaceName != null && { namespace: namespaceName }),
        })
        if (decision.action === "reject") {
          return c.json({ error: decision.error }, decision.status as any)
        }
      }

      const documentKey = resolveDocumentKey(col.storagePath, params)
      // Guard the resolved key before any store read. The JSON branch re-checks
      // inside handleSyncPull, but the binary `getBytes` branch below reads the
      // store directly — without this, a non-`{identity}` param of `..` (which
      // passes the per-segment charset check) would traverse the composed key.
      if (isUnsafeDocumentKey(documentKey)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      // Binary collection: return raw bytes
      if (!isJsonCollection(col.allowedMimeTypes)) {
        if (!opts.store.getBytes) {
          return c.json({ error: "Store does not support binary operations" }, 501)
        }
        const result = await opts.store.getBytes(documentKey, pullCtx)
        if (result == null) {
          return new Response(null, { status: 404 })
        }
        return binaryPullResponse(
          c,
          result.body,
          result.contentType,
          col.cacheDurationMs,
          col.readRoles.includes(ROLE_PUBLIC),
        )
      }

      // Let plugins intercept the pull and serve a binary response (e.g. an
      // events plugin that stores Parquet instead of a JSON document).
      if (opts.plugins?.some((p) => p.interceptPull)) {
        const interceptResult = await dispatchInterceptPull(opts.plugins, {
          collection: col.name,
          params,
          ...(namespaceName != null && { namespace: namespaceName }),
        })
        if (interceptResult.action === "respond") {
          return binaryPullResponse(
            c,
            interceptResult.body,
            interceptResult.contentType,
            col.cacheDurationMs,
            col.readRoles.includes(ROLE_PUBLIC),
          )
        }
      }

      const store = opts.store
      const checkpointParam = c.req.query(QUERY_CHECKPOINT)
      const isPublic = col.readRoles.includes(ROLE_PUBLIC)

      const lastParam = c.req.query(QUERY_LAST)
      const limitParam = c.req.query(QUERY_LIMIT)
      const fullParam = c.req.query(QUERY_FULL)
      let withKeyring = isWithKeyringEnabled(c.req.query("withKeyring"))
      // The sibling `<key>/_keyring` read must be authorized like any other
      // path: a cap that denies the keyring (e.g. scopes.writer) must not read
      // it via this shortcut. Drop the optimization when the caller's cap scope
      // does not cover the keyring key. An undefined scope (role-based auth, no
      // path scope) leaves the optimization enabled.
      if (withKeyring) {
        const capScopePaths = scopePathsByContext.get(c)
        if (capScopePaths !== undefined && !matchScopePath(`${documentKey}/_keyring`, capScopePaths)) {
          withKeyring = false
        }
      }
      // AppendOnly persist=true filters its {ts,data} array by `?checkpoint=`;
      // regular collections always return the full document.
      const pullResult = col.appendOnly != null && col.appendOnly.persist !== false
        ? await handleAppendOnlyPull(
            documentKey,
            store,
            checkpointParam,
            col.appendOnly?.field ?? APPEND_DEFAULT_FIELD,
            col.cacheDurationMs,
            isPublic,
            lastParam,
            pullCtx,
            limitParam,
            fullParam,
            {
              allowFull: col.appendOnly?.allowFull,
              maxPullLimit: col.appendOnly?.maxPullLimit,
              maxCheckpointAgeMs: col.appendOnly?.maxCheckpointAgeMs,
            },
          )
        : await handleSyncPull(
            documentKey,
            store,
            col.cacheDurationMs,
            isPublic,
            pullCtx,
            withKeyring,
          )

      // TTL check: compare the *stored* document write-time against now.
      // pullResult.body["timestamp"] is Date.now() at pull time (not the stored write time),
      // so we read the stored doc-level `ts` directly (falling back to the legacy
      // per-field `timestamps` tree for documents written before this version).
      if (col.ttlMs != null && pullResult.status === 200) {
        try {
          const rawDoc = await store.getString(documentKey, pullCtx)
          if (rawDoc) {
            const stored = JSON.parse(rawDoc) as { ts?: number }
            const storedTs = stored.ts ?? 0
            if (isExpired(storedTs, col.ttlMs)) {
              const currentTs = pullResult.body["timestamp"] as number
              pullResult.body = { data: {}, hash: "", timestamp: currentTs }
            }
          }
        } catch {
          // Corrupt document — already handled by pull(); skip TTL check
        }
      }

      // Field-level read permissions: strip fields the user can't read
      if (pullResult.status === 200) {
        applyFieldReadFilter(
          pullResult.body["data"],
          col.fieldPermissions,
          roles,
          col.appendOnly != null && col.appendOnly.persist !== false
            ? (col.appendOnly.field ?? APPEND_DEFAULT_FIELD)
            : undefined,
        )
      }

      // ETag conditional request support
      const hash = pullResult.body["hash"] as string | undefined
      if (hash) {
        const etag = `"${hash}"`
        const ifNoneMatch = c.req.header("if-none-match")
        if (ifNoneMatch === etag) {
          return new Response(null, { status: 304 })
        }
        if (!pullResult.headers) pullResult.headers = {}
        pullResult.headers["ETag"] = etag
      }

      // Audit logging
      if (opts.auditLogger) {
        await opts.auditLogger.record({
          timestamp: Date.now(),
          action: "pull",
          collection: col.name,
          identity,
          documentKey,
          success: pullResult.status === 200,
          statusCode: pullResult.status,
          params,
        })
      }

      if (pullResult.headers) {
        const res = c.json(pullResult.body, pullResult.status as any)
        for (const [k, v] of Object.entries(pullResult.headers)) {
          res.headers.set(k, v)
        }
        return res
      }
      return c.json(pullResult.body, pullResult.status as any)
    })
  }

  if (col.listable) {
    const listPath = toListRoutePath(col.storagePath)

    app.get(listPath, async (c) => {
      const rawParams = c.req.param()
      // For the list route the last param segment is absent from the URL,
      // so we resolve only the prefix portion of storagePath.
      const prefixSegments = col.storagePath.split("/").slice(0, -1).join("/")
      const params = extractPathParams(prefixSegments, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity: listIdentity, roles: listRoles, error } = await checkAuth(col, OP_READ, c, params, opts, ACTION_LIST, namespaceName)
      if (error) return error

      if (limiters.list) {
        const rateErr = await checkRateLimiters(limiters.list, listIdentity ?? null, c.req.header("x-forwarded-for") ?? null)
        if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)
      }

      const listCtx: StoreContext = {
        collection: col.name,
        params,
        identity: listIdentity,
        roles: listRoles,
        action: ACTION_LIST,
        ...(namespaceName != null && { namespace: namespaceName }),
      }

      const prefix = toListPrefix(col.storagePath, params)

      // Parse pagination params
      let limit = LIST_DEFAULT_LIMIT
      const limitParam = c.req.query("limit")
      if (limitParam != null) {
        const parsed = parseInt(limitParam, 10)
        if (isNaN(parsed) || parsed <= 0 || String(parsed) !== limitParam) {
          return c.json({ error: "Invalid limit parameter" }, 400)
        }
        limit = Math.min(parsed, LIST_MAX_LIMIT)
      }

      // Reconstruct the full storage key for cursor-based pagination
      let startAfter: string | undefined
      const afterParam = c.req.query("after")
      if (afterParam != null) {
        startAfter = prefix + afterParam
      }

      // Fetch one extra to detect hasMore without an additional query
      const keys = await opts.store.listKeys(prefix, { startAfter, limit: limit + 1 }, listCtx)
      const hasMore = keys.length > limit
      const page = hasMore ? keys.slice(0, limit) : keys

      // Strip the prefix to return only the last-param values
      const items = page.map((k) => k.slice(prefix.length))

      return c.json({ items, hasMore })
    })
  }

  if (!col.pullOnly) {
    const pushPath = toRoutePath(ACTION_PUSH, col.storagePath)
    const rateLimiter = limiters.push ?? []

    app.post(pushPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(col.storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error, presenter } = await checkAuth(col, OP_WRITE, c, params, opts, ACTION_PUSH, namespaceName)
      if (error) return error

      // Push-intercepting plugins (e.g. starfish-replica): reject read-only
      // collections, or respond on the route's behalf (e.g. proxy the write to
      // a primary). The raw text body is read once for the hook (Hono caches
      // it, so the local push path below re-parses without re-reading).
      if (opts.plugins?.some((p) => p.interceptPush)) {
        const rawBody = isJsonCollection(col.allowedMimeTypes) ? await c.req.text() : ""
        const decision = await dispatchInterceptPush(opts.plugins, {
          collection: col.name,
          params,
          rawBody,
          ...(namespaceName != null && { namespace: namespaceName }),
        })
        if (decision.action === "reject" || decision.action === "respond") {
          // Push-through / rejected writes still pass local auth, so record them
          // in the audit log (they otherwise returned before the audit call
          // below, leaving proxied writes invisible). No WriteEvent is emitted:
          // the write lands on the primary, not the local store, so the primary
          // owns that change event.
          if (opts.auditLogger) {
            await opts.auditLogger.record({
              timestamp: Date.now(),
              action: "push",
              collection: col.name,
              identity,
              documentKey: resolveDocumentKey(col.storagePath, params),
              success: decision.status >= 200 && decision.status < 300,
              statusCode: decision.status,
              params,
            })
          }
          const responseBody = decision.action === "reject" ? { error: decision.error } : decision.body
          return c.json(responseBody as any, decision.status as any)
        }
      }

      // Field-level write permissions are enforced inside runPush (covers the
      // bundle push path too); the resolved `roles` are passed via pushCtx below.

      const documentKey = resolveDocumentKey(col.storagePath, params)
      // Guard the resolved key against traversal/injection BEFORE any store write.
      // `validateAllParams` only constrains each param's charset (it admits `..`),
      // so a `..`-bearing param can compose a traversal key. The pull path guards
      // here; the binary and append-only push paths write the store directly, so
      // they must reject an unsafe resolved key too (mirrors handleSyncPull).
      if (isUnsafeDocumentKey(documentKey)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }
      const pushCtx: StoreContext = {
        collection: col.name,
        params,
        identity,
        roles,
        action: ACTION_PUSH,
        ...(namespaceName != null && { namespace: namespaceName }),
      }

      if (!isJsonCollection(col.allowedMimeTypes)) {
        const response = await runBinaryPush(c, col, documentKey, identity, rateLimiter, opts, pushCtx)
        await emitWriteEvent(opts, col, response, params, identity, undefined, namespaceName)
        if (opts.auditLogger) {
          await opts.auditLogger.record({ timestamp: Date.now(), action: "push", collection: col.name, identity, documentKey, success: response.status === 200, statusCode: response.status, params })
        }
        return response
      }

      // Pre-extract the request `data` object so plugins' afterWrite hooks can
      // see the pushed body. Hono caches the parsed JSON, so runPush's own parse
      // below does not re-read the stream. A plugin decides whether to use it.
      let bodyData: Record<string, unknown> | undefined
      if (opts.plugins?.some((p) => p.afterWrite)) {
        try {
          const raw = (await c.req.json()) as Record<string, unknown>
          const d = raw[DATA_FIELD]
          if (d !== null && typeof d === "object" && !Array.isArray(d)) {
            bodyData = d as Record<string, unknown>
          }
          // Non-object data → bodyData stays undefined; a plugin that wanted the
          // body warns on its side.
        } catch {
          // JSON parse failed → bodyData stays undefined. runPush re-parses and
          // rejects with 400, so the non-200 guard skips dispatch anyway.
        }
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts, pushCtx, presenter)
      await emitWriteEvent(opts, col, response, params, identity, bodyData, namespaceName)
      if (opts.auditLogger) {
        await opts.auditLogger.record({ timestamp: Date.now(), action: "push", collection: col.name, identity, documentKey, success: response.status === 200, statusCode: response.status, params })
      }
      return response
    })
  }
}

function addBundledRoutes(
  app: Hono,
  bundleName: string,
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
  namespaceName?: string,
): void {
  const storagePath = collections[0]!.storagePath
  const pullPath = toRoutePath(ACTION_PULL, storagePath)
  // A bundle member is "public" when its own readRoles allow ROLE_PUBLIC.
  // Non-public members (including rootOnly ones) are each authorized against the
  // caller's resolved roles; a public member of the bundle never relaxes a
  // private sibling.
  const hasNonPublic = collections.some(
    (col) => col.rootOnly || !col.readRoles.includes(ROLE_PUBLIC),
  )

  app.get(pullPath, async (c) => {
    const rawParams = c.req.param()
    const params = extractPathParams(storagePath, rawParams)
    if (!validateAllParams(params)) {
      return c.json({ error: "Invalid path parameter" }, 400)
    }

    // Resolve the caller's effective roles ONCE (the resolver consumes the
    // request nonce, so it must not run per-collection). Skipped entirely when
    // every member is public, preserving anonymous access to all-public bundles
    // — unless an authorize hook is installed, in which case the identity must
    // be resolved so identity restrictions apply even to all-public bundles.
    let identity: string | null = null
    let effectiveRoles = new Set<string>()
    if (hasNonPublic || hasAuthorizeHook(opts.plugins)) {
      const authResult = await resolveEffectiveRoles(c, params, opts, storagePath)
      if (authResult.error) return authResult.error
      identity = authResult.identity
      effectiveRoles = authResult.roles
    }

    const baseKey = resolveDocumentKey(storagePath, params)
    // Guard the resolved key: the per-member loop below reads the store directly
    // (it does not go through handleSyncPull), so a `..` in a non-`{identity}`
    // param would otherwise traverse the composed bundle key.
    if (isUnsafeDocumentKey(baseKey)) {
      return c.json({ error: "Invalid path parameter" }, 400)
    }
    const store = opts.store

    // Bundles contain only regular collections, which always return the full
    // document — `?checkpoint=` is no longer honored (appendOnly-only feature).
    const result: Record<string, Record<string, unknown>> = {}
    let latestTimestamp = 0

    for (const col of collections) {
      // Per-collection authorization via the shared decision so a bundle pull
      // enforces exactly what the standalone pull does (readRoles, public, and
      // rootOnly). Denied members are omitted so a bundle never leaks a
      // collection the caller can't read.
      if (!isAccessAllowed(col, OP_READ, effectiveRoles)) continue

      // Identity restrictions: a restricted member is omitted (not leaked),
      // matching how a role-denied member is dropped above.
      const memberAuthz = await dispatchAuthorize(opts.plugins, {
        ...(identity != null && identity !== "" && { identity }),
        action: ACTION_PULL,
        collection: col.name,
        ...(namespaceName != null && { namespace: namespaceName }),
        params,
        roles: [...effectiveRoles],
      })
      if (memberAuthz.action === "reject") continue

      const documentKey = `${baseKey}/${col.name}`
      const bundlePullCtx: StoreContext = {
        collection: col.name,
        params,
        identity,
        roles: [...effectiveRoles],
        action: ACTION_PULL,
        ...(namespaceName != null && { namespace: namespaceName }),
      }
      const pullResult = await pull(store, documentKey, bundlePullCtx)
      // Strip fields the caller cannot read (parity with the standalone path).
      applyFieldReadFilter(pullResult.data, col.fieldPermissions, effectiveRoles)
      result[col.name] = {
        data: pullResult.data,
        hash: pullResult.hash,
      }
      if (pullResult.timestamp > latestTimestamp) {
        latestTimestamp = pullResult.timestamp
      }
    }

    return c.json({ collections: result, timestamp: latestTimestamp })
  })

  for (const col of collections) {
    if (col.pullOnly) continue

    const pushPath = toRoutePath(ACTION_PUSH, storagePath) + `/${col.name}`
    const rateLimiter = buildActionRateLimiters(col.rateLimit, opts, `${namespaceName ?? ""}/${bundleName}/${col.name}`).push ?? []

    app.post(pushPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error, presenter } = await checkAuth(col, OP_WRITE, c, params, opts, ACTION_PUSH, namespaceName)
      if (error) return error

      const documentKey = `${resolveDocumentKey(storagePath, params)}/${col.name}`
      const bundlePushCtx: StoreContext = {
        collection: col.name,
        params,
        identity,
        roles,
        action: ACTION_PUSH,
        ...(namespaceName != null && { namespace: namespaceName }),
      }

      // See the JSON-push handler: pre-extract `data` for plugins' afterWrite
      // hooks; Hono caches the parse so runPush below does not re-read.
      let bundleBodyData: Record<string, unknown> | undefined
      if (opts.plugins?.some((p) => p.afterWrite)) {
        try {
          const raw = (await c.req.json()) as Record<string, unknown>
          const d = raw[DATA_FIELD]
          if (d !== null && typeof d === "object" && !Array.isArray(d)) {
            bundleBodyData = d as Record<string, unknown>
          }
        } catch {
          // parse failure → bundleBodyData undefined; non-200 guard skips dispatch
        }
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts, bundlePushCtx, presenter)
      await emitWriteEvent(opts, col, response, params, identity, bundleBodyData, namespaceName)
      return response
    })
  }
}

function registerCollectionsOnApp(
  app: Hono,
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
  namespaceName?: string,
): void {
  const bundles = new Map<string, CollectionConfig[]>()
  const standalone: CollectionConfig[] = []

  for (const col of collections) {
    if (col.bundle) {
      const existing = bundles.get(col.bundle) ?? []
      existing.push(col)
      bundles.set(col.bundle, existing)
    } else {
      standalone.push(col)
    }
  }

  for (const col of standalone) {
    addCollectionRoutes(app, col, opts, namespaceName)
  }

  for (const [bundleName, bundleCollections] of bundles) {
    addBundledRoutes(app, bundleName, bundleCollections, opts, namespaceName)
  }
}

function createBatchPullHandler(
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
  namespaceName?: string,
) {
  return async (c: Context) => {
    // 400 only when `collections` itself is absent/empty; once present, empty CSV
    // slots (`,a,,`) are dropped rather than turned into spurious `""` →
    // "Collection not found" entries. An all-empty `,,` therefore resolves to no
    // names and returns `{ collections: {} }`. (Parity with the Python handler.)
    const rawCollections = c.req.query("collections")
    if (!rawCollections) {
      return c.json({ error: "Missing collections parameter" }, 400)
    }
    // De-duplicate (preserving order): the result map is keyed by name, so a
    // repeated name only ever overwrote itself — deduping makes that explicit and
    // stops `?collections=a,a,a,…` from driving repeated reads of one document.
    const colNames = [
      ...new Set(
        rawCollections
          .split(",")
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      ),
    ]

    // Bound the per-request work: one signed request fans out to a store read +
    // enricher + scope check per collection, and the rate limiter caps requests,
    // not work-per-request. Reject an oversized batch (distinct names) up front.
    const maxBatch = opts.maxCollectionsPerBatch ?? DEFAULT_MAX_BATCH_COLLECTIONS
    if (colNames.length > maxBatch) {
      return c.json({ error: "Too many collections" }, 400)
    }

    // Optional `params`: URL-encoded JSON mapping collection name → an ARRAY of
    // path-param sets, one per document to read from that collection, e.g.
    // `{"profile":[{"identity":"a"},{"identity":"b"}]}` reads two profiles.
    // `{identity}` is auto-filled from the caller below, so a set may omit it. A
    // malformed blob is a client framing error → whole-request 400, rather than
    // silently dropping params for every collection.
    let paramsByCollection: Record<string, Record<string, unknown>[]> = {}
    const rawParams = c.req.query("params")
    if (rawParams != null && rawParams.length > 0) {
      let parsed: unknown
      try {
        parsed = JSON.parse(rawParams)
      } catch {
        return c.json({ error: "Invalid params parameter" }, 400)
      }
      if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return c.json({ error: "Invalid params parameter" }, 400)
      }
      // Each value is an array of param-sets; every element must be a plain object.
      // An array of arrays/scalars (or a bare object) is a framing error → 400.
      for (const v of Object.values(parsed as Record<string, unknown>)) {
        if (
          !Array.isArray(v) ||
          v.some((e) => e == null || typeof e !== "object" || Array.isArray(e))
        ) {
          return c.json({ error: "Invalid params parameter" }, 400)
        }
      }
      paramsByCollection = parsed as Record<string, Record<string, unknown>[]>
    }

    // Optional `appendParams`: URL-encoded JSON mapping collection name → an ARRAY
    // of per-entry append options index-aligned to that collection's `params` array.
    // Absent ⇒ regular full-document pull. Malformed → whole-request 400.
    // `full` is disallowed in batch to prevent oversized responses.
    type BatchAppendOpts = {
      since?: number
      last?: number
      limit?: number
    }
    let appendParamsByCollection: Record<string, (BatchAppendOpts | null)[]> = {}
    const rawAppendParams = c.req.query("appendParams")
    if (rawAppendParams != null && rawAppendParams.length > 0) {
      let parsedAP: unknown
      try {
        parsedAP = JSON.parse(rawAppendParams)
      } catch {
        return c.json({ error: "Invalid appendParams parameter" }, 400)
      }
      if (parsedAP == null || typeof parsedAP !== "object" || Array.isArray(parsedAP)) {
        return c.json({ error: "Invalid appendParams parameter" }, 400)
      }
      for (const [col, v] of Object.entries(parsedAP as Record<string, unknown>)) {
        if (!Array.isArray(v)) {
          return c.json({ error: "Invalid appendParams parameter" }, 400)
        }
        const coerced: (BatchAppendOpts | null)[] = []
        for (const e of v) {
          if (e == null) { coerced.push(null); continue }
          if (typeof e !== "object" || Array.isArray(e)) {
            return c.json({ error: "Invalid appendParams parameter" }, 400)
          }
          const ap = e as Record<string, unknown>
          // `full` is unconditionally rejected in batch (prevents oversized responses).
          if (ap.full === true || ap.full === 1 || ap.full === "true" || ap.full === "1") {
            return c.json({ error: `appendParams["${col}"]: full is not allowed in batch pull` }, 400)
          }
          const parseIntBound = (v: unknown): number | undefined | "invalid" => {
            if (v == null) return undefined
            const n = Number(v)
            if (!Number.isInteger(n) || n < 0) return "invalid"
            return n
          }
          const since = parseIntBound(ap.since)
          const last = parseIntBound(ap.last)
          const limit = parseIntBound(ap.limit)
          if (since === "invalid" || last === "invalid" || limit === "invalid") {
            return c.json({ error: "Invalid appendParams parameter" }, 400)
          }
          coerced.push({
            ...(since != null && { since }),
            ...(last != null && { last }),
            ...(limit != null && { limit }),
          })
        }
        appendParamsByCollection[col] = coerced
      }
    }

    // Length-equality guard: appendParams[col] must align index-for-index with
    // params[col]. A mismatch would silently give trailing entries null append-opts
    // (falling back to an unbounded full-document read of an append log).
    for (const [col, apArr] of Object.entries(appendParamsByCollection)) {
      const pArr = paramsByCollection[col]
      if (pArr != null && apArr.length !== pArr.length) {
        return c.json({ error: "appendParams length mismatch: must equal params length for each collection" }, 400)
      }
    }

    // Bound the TOTAL reads (Σ param-sets across collections), not just the count
    // of distinct names: with array params one name can fan in many documents, so
    // the distinct-name cap above is necessary but no longer sufficient. A name
    // absent from `params` reads one auto-filled doc (counts as 1).
    const totalReads = colNames.reduce(
      (n, name) => n + (paramsByCollection[name]?.length ?? 1),
      0,
    )
    if (totalReads > maxBatch) {
      return c.json({ error: "Too many collections" }, 400)
    }

    // Aggregate append-element budget: prevent 100×maxPullLimit amplification even
    // when full is rejected per-entry. Sum the effective last/limit per entry,
    // clamped to each collection's maxPullLimit (or a fallback ceiling).
    if (Object.keys(appendParamsByCollection).length > 0) {
      const maxTotal = opts.maxBatchAppendElements ?? 5000
      let totalAppendElements = 0
      for (const [col, apArr] of Object.entries(appendParamsByCollection)) {
        const colCfg = collections.find((c) => c.name === col)
        const colMax = colCfg?.appendOnly?.maxPullLimit ?? 1000
        for (const ap of apArr) {
          if (ap == null) continue
          const effective = Math.min(ap.last ?? ap.limit ?? colMax, colMax)
          totalAppendElements += effective
        }
      }
      if (totalAppendElements > maxTotal) {
        return c.json({ error: "Batch append element budget exceeded" }, 400)
      }
    }

    // Resolve the caller's base auth ONCE — the resolver consumes the request
    // nonce, so it must not run per-collection. Per-collection `self`/enricher
    // roles are folded below from this single resolve. A resolver error is NOT
    // fatal to the batch: it degrades to anonymous so public collections still
    // resolve and private ones return per-collection "Forbidden", matching the
    // pre-params handler (which authorized each collection independently and
    // mapped any auth error to a per-collection "Forbidden").
    const base = await resolveBaseAuth(c, opts)
    const identity = base.auth != null ? base.identity : null
    // Cap-scoped auth carries `scope.paths`; the resolver skips its URL path-scope
    // check for /batch/pull (the URL names no storage path), so we re-check each
    // RESOLVED key against this scope below. `undefined` (role-based auth or an
    // unrestricted device cap) imposes no restriction (matchScopePath → true).
    const scopePaths = scopePathsByContext.get(c)

    // Audit: mirror the standalone pull's points — a per-collection record on each
    // auth denial (403/500) and successful read. Awaited like the standalone path.
    // (The 400-class missing/invalid-param branches are NOT audited, matching the
    // standalone path which only audits via checkAuth's auth-layer denials.)
    const recordAudit = async (
      collection: string,
      documentKey: string,
      success: boolean,
      statusCode: number,
      auditParams: Record<string, string>,
    ): Promise<void> => {
      try {
        await opts.auditLogger?.record({
          timestamp: Date.now(),
          action: ACTION_PULL,
          collection,
          identity,
          documentKey,
          success,
          statusCode,
          // Snapshot: the entry may be persisted/async-processed by the logger,
          // so copy rather than alias the live per-collection params object.
          params: { ...auditParams },
        })
      } catch (e) {
        // Audit is best-effort here: the success record runs inside the per-
        // collection read try/catch, so a throwing logger must NOT relabel a
        // successful read as "Internal error" (nor 500 the whole batch from the
        // request-level degrade record). Log and continue. This intentionally
        // diverges from the standalone path, which lets an audit throw propagate —
        // tolerable for a single-document request, not for a multi-collection one.
        console.error("[Starfish] Batch pull audit record failed:", e)
      }
    }
    // The resolver hard-failed but we degrade to anonymous (so public collections
    // still resolve) — record it so a revoked/expired/bad-sig cap is not an audit
    // blind spot. `collection: ""` marks it a request-level event.
    if (base.error) {
      await recordAudit("", "", false, base.error.status, {})
    }

    const store = opts.store

    // Resolve ONE document of `col` for a single supplied param-set, returning its
    // result entry (`{ data, hash, timestamp }` or `{ error }`). Factored out of
    // the loop so a collection's array of param-sets each runs the identical
    // params → auth-fold → access → key → scope → pull → field-filter pipeline.
    // When `appendOpts` is non-null, dispatches to `handleAppendOnlyPull` instead
    // of the regular `pull()`, returning the bounded-tail array in `data[appendField]`.
    type BatchAppendOptsLocal = { since?: number; last?: number; limit?: number }
    const resolveEntry = async (
      col: CollectionConfig,
      supplied: Record<string, unknown>,
      appendOpts?: BatchAppendOptsLocal | null,
    ): Promise<Record<string, unknown>> => {
      // Effective params built from ONLY the template's params (parity with the
      // standalone path's `extractPathParams`): caller-supplied keys outside the
      // template are ignored, so they can't reach the store context, plugins, or
      // audit log. Values must be string/number. `{identity}` auto-fills from the
      // authenticated caller when the path needs it and none was supplied; an
      // explicitly supplied identity is kept as-is, so a forged identity is denied
      // below via the missing-`self` path rather than silently rewritten.
      const requiredParams = (col.storagePath.match(/\{(\w+)\}/g) ?? []).map((t) => t.slice(1, -1))
      const effectiveParams: Record<string, string> = {}
      for (const p of requiredParams) {
        const v = supplied[p]
        if (typeof v === "string" || typeof v === "number") effectiveParams[p] = String(v)
      }
      if (
        requiredParams.includes(IDENTITY_KEY) &&
        effectiveParams[IDENTITY_KEY] == null &&
        identity
      ) {
        // `identity` truthy excludes both null and the anonymous "" — an
        // anonymous caller has no identity to bind, so `{identity}` falls through
        // to the missing-required-param guard below (no degenerate empty key).
        effectiveParams[IDENTITY_KEY] = identity
      }

      // A required param with no supplied/auto-filled value cannot be addressed.
      if (requiredParams.some((p) => effectiveParams[p] == null)) {
        return { error: "Missing required path parameter" }
      }
      // Charset-validate each value (blocks `/` and other unsafe chars per segment).
      if (!validateAllParams(effectiveParams)) {
        return { error: "Invalid path parameter" }
      }

      // Fold per-collection `self` + enricher roles from the single base resolve.
      // Anonymous (or degraded) callers carry no roles, so only public-read
      // collections pass isAccessAllowed below.
      let roles: Set<string>
      if (base.auth != null) {
        const folded = await foldCollectionRoles(base.auth, base.baseRoles, effectiveParams, col.storagePath, opts, c)
        if (folded.error) {
          await recordAudit(col.name, "", false, 500, effectiveParams)
          return { error: "Authorization error" }
        }
        roles = folded.roles
      } else {
        roles = new Set()
      }

      if (!isAccessAllowed(col, OP_READ, roles)) {
        await recordAudit(col.name, "", false, 403, effectiveParams)
        return { error: "Forbidden" }
      }

      // Identity restrictions: deny by identity independent of roles (parity
      // with the standalone pull path).
      const batchAuthz = await dispatchAuthorize(opts.plugins, {
        ...(identity != null && identity !== "" && { identity }),
        action: ACTION_PULL,
        collection: col.name,
        ...(namespaceName != null && { namespace: namespaceName }),
        params: effectiveParams,
        roles: [...roles],
      })
      if (batchAuthz.action === "reject") {
        await recordAudit(col.name, "", false, batchAuthz.status, effectiveParams)
        return { error: batchAuthz.error }
      }

      try {
        const key = resolveDocumentKey(col.storagePath, effectiveParams)
        // Guard the resolved key: `validatePathSegment` admits `..`, so a supplied
        // param could compose a traversal key. Reject before touching the store
        // (parity with the standalone and bundle pull paths).
        if (isUnsafeDocumentKey(key)) {
          return { error: "Invalid path parameter" }
        }
        // Cap path-scope: the resolver couldn't bind /batch/pull to a storage
        // path, so enforce the cap's scope against the RESOLVED key here — a cap
        // may only batch-read keys its scope covers (e.g. its own room, not a
        // sibling). This is what stops batch from side-stepping per-path scope.
        if (!matchScopePath(key, scopePaths)) {
          await recordAudit(col.name, key, false, 403, effectiveParams)
          return { error: "Forbidden" }
        }
        // Key denylist: reject sensitive sibling collections even if the enricher
        // granted roles. Defense-in-depth for enricher-authorized batch routes.
        const denySuffixes = opts.batchKeyDenySuffixes ?? ["_keyring", "_members"]
        if (denySuffixes.some((s) => key === s || key.endsWith("/" + s))) {
          await recordAudit(col.name, key, false, 403, effectiveParams)
          return { error: "Forbidden" }
        }
        const batchCtx: StoreContext = {
          collection: col.name,
          params: effectiveParams,
          identity,
          roles: [...roles],
          action: ACTION_PULL,
          ...(namespaceName != null && { namespace: namespaceName }),
        }

        // ── Append-aware branch ──────────────────────────────────────────────
        if (appendOpts != null) {
          // Reject appendParams for non-append-only collections.
          if (!col.appendOnly || col.appendOnly.persist === false) {
            await recordAudit(col.name, key, false, 400, effectiveParams)
            return { error: ERROR_APPEND_PARAMS_NOT_SUPPORTED }
          }
          const appendCfg = col.appendOnly
          const appendField = appendCfg.field ?? APPEND_DEFAULT_FIELD
          const bounds: AppendPullBounds | undefined = (() => {
            const b: AppendPullBounds = {}
            if (appendCfg.allowFull === false) b.allowFull = false
            if (appendCfg.maxPullLimit != null) b.maxPullLimit = appendCfg.maxPullLimit
            if (appendCfg.maxCheckpointAgeMs != null) b.maxCheckpointAgeMs = appendCfg.maxCheckpointAgeMs
            return Object.keys(b).length > 0 ? b : undefined
          })()
          // `since` maps directly to `checkpoint` in handleAppendOnlyPull — both
          // mean "return elements with ts strictly greater than this value". A
          // checkpoint of 0 with no `last`/`limit` is rejected as pull_bound_required
          // (same as standalone), so `since` alone without a last/limit bound is an
          // error. Callers must pair `since=0` with a `last` or `limit`.
          const appendResp = await handleAppendOnlyPull(
            key,
            store,
            appendOpts.since != null ? String(appendOpts.since) : null,  // since → checkpoint
            appendField,
            col.cacheDurationMs,
            false,                                  // isPublic=false — roles already checked
            appendOpts.last != null ? String(appendOpts.last) : null,
            batchCtx,
            appendOpts.limit != null ? String(appendOpts.limit) : null,
            null,                                   // full=null — disallowed in batch
            bounds,
          )
          // Map non-200 PullResponse status codes → per-entry error strings.
          if (appendResp.status !== 200) {
            const errCode = (appendResp.body as { error?: string }).error ?? "Internal error"
            await recordAudit(col.name, key, false, appendResp.status, effectiveParams)
            return { error: errCode }
          }
          // PullResponse.body = { data: { [appendField]: [...] }, hash, timestamp }.
          // Unwrap body.data so the batch entry shape is consistent with full-doc pulls.
          const appendRespBody = appendResp.body as { data: Record<string, unknown>; hash: string; timestamp: number }
          const appendData = { ...appendRespBody.data }
          // Re-apply field-read filter + TTL: handleAppendOnlyPull does not strip fieldPermissions
          applyFieldReadFilter(appendData, col.fieldPermissions, roles, appendField)
          if (col.ttlMs != null) {
            try {
              const rawDoc = await store.getString(key, batchCtx)
              if (rawDoc) {
                const stored = JSON.parse(rawDoc) as { ts?: number }
                if (isExpired(stored.ts ?? 0, col.ttlMs)) {
                  appendData[appendField] = []
                }
              }
            } catch { /* corrupt doc — skip TTL */ }
          }
          await recordAudit(col.name, key, true, 200, effectiveParams)
          return { data: appendData, hash: appendRespBody.hash ?? null, timestamp: appendRespBody.timestamp }
        }

        // ── Regular (full-document) branch ────────────────────────────────────
        const pullResult = await pull(store, key, batchCtx)
        let data = pullResult.data
        // TTL: pull() returns now as its timestamp, so read the stored doc-level
        // write-time to expire stale documents — parity with the standalone pull
        // path (and the Python batch handler).
        if (col.ttlMs != null) {
          try {
            const rawDoc = await store.getString(key, batchCtx)
            if (rawDoc) {
              const stored = JSON.parse(rawDoc) as { ts?: number }
              if (isExpired(stored.ts ?? 0, col.ttlMs)) {
                data = {}
              }
            }
          } catch {
            // Corrupt document — already handled by pull(); skip TTL check.
          }
        }
        // Strip fields the caller cannot read (parity with the standalone path).
        applyFieldReadFilter(data, col.fieldPermissions, roles)
        await recordAudit(col.name, key, true, 200, effectiveParams)
        return { data, hash: pullResult.hash, timestamp: pullResult.timestamp }
      } catch (e) {
        console.error(`[Starfish] Batch pull failed for collection "${col.name}":`, e)
        return { error: "Internal error" }
      }
    }

    // Build a name → config Map once so each per-name lookup is O(1) instead of
    // O(C) (linear scan). With B names and C collections, the loop is O(B·C)
    // without the map; the map makes it O(C + B).
    const collectionByName = new Map(collections.map((cc) => [cc.name, cc]))

    const results: Record<string, Record<string, unknown>[]> = {}
    for (const name of colNames) {
      // A name absent from `params` reads one auto-filled doc (`[{}]`); present
      // means an array of param-sets, possibly empty (→ no reads, `[]`).
      const paramSets = paramsByCollection[name] ?? [{}]
      const col = collectionByName.get(name)
      if (!col) {
        // One error entry PER requested set so the array stays index-aligned with
        // the caller's input (batchPullMany indexes results by position).
        results[name] = paramSets.map(() => ({ error: "Collection not found" }))
        continue
      }
      const colAppendParams = appendParamsByCollection[name]
      const entries: Record<string, unknown>[] = []
      for (let i = 0; i < paramSets.length; i++) {
        const supplied = paramSets[i] ?? {}
        const appendOpts = colAppendParams != null ? (colAppendParams[i] ?? null) : null
        entries.push(await resolveEntry(col, supplied, appendOpts))
      }
      results[name] = entries
    }

    return c.json({ collections: results })
  }
}

function mountNamespace(
  app: Hono,
  nsName: string,
  nsConfig: NamespaceConfig,
  opts: SyncRouterOptions,
): void {
  const nsApp = new Hono()
  registerCollectionsOnApp(nsApp, nsConfig.collections, opts, nsName)
  nsApp.get("/batch/pull", createBatchPullHandler(nsConfig.collections, opts, nsName))
  app.route(`/${nsName}`, nsApp)
}

function toCollectionClientInfo(col: CollectionConfig): CollectionClientInfo {
  const info: CollectionClientInfo = {
    name: col.name,
    maxBodyBytes: col.maxBodyBytes,
    encryption: col.encryption,
    allowedMimeTypes: col.allowedMimeTypes,
  }
  if (col.pullOnly) info.pullOnly = true
  if (col.pushOnly) info.pushOnly = true
  if (col.appendOnly) info.appendOnly = col.appendOnly
  if (col.ttlMs != null) info.ttlMs = col.ttlMs
  if (col.forceFullFetch) info.forceFullFetch = true
  return info
}

export function createSyncRouter(opts: SyncRouterOptions): Hono {
  const app = new Hono()
  const config = opts.config

  // `appendOnly.persist=false` computes a hash and emits a write event without
  // writing to storage — it only does something useful when a plugin consumes
  // the event (e.g. `starfish-queuing`). Warn if no afterWrite hook is wired.
  if (!(opts.plugins ?? []).some((p) => p.afterWrite)) {
    const allCols = [
      ...config.collections,
      ...Object.values(config.namespaces ?? {}).flatMap((n) => n.collections),
    ]
    const queueOnly = allCols.filter((col) => col.appendOnly?.persist === false)
    if (queueOnly.length > 0) {
      console.warn(
        `[Starfish] appendOnly.persist=false on collection(s) ${queueOnly
          .map((c) => `"${c.name}"`)
          .join(", ")} but no plugin with an afterWrite hook is registered; ` +
          `pushes will be neither stored nor published.`,
      )
    }
  }

  // Identity restrictions declared in config are inert unless an authorize-hook
  // plugin (e.g. createRestrictionsPlugin from starfish-restrictions) ingests
  // them. Silently-ignored security policy is dangerous, so warn loudly.
  if (!hasAuthorizeHook(opts.plugins)) {
    const declaresRestrictions =
      (config.restrictions?.length ?? 0) > 0 ||
      config.collections.some((c) => (c.restrictions?.length ?? 0) > 0) ||
      Object.values(config.namespaces ?? {}).some(
        (n) =>
          (n.restrictions?.length ?? 0) > 0 ||
          n.collections.some((c) => (c.restrictions?.length ?? 0) > 0),
      )
    if (declaresRestrictions) {
      console.warn(
        "[Starfish] config declares `restrictions` but no plugin provides an " +
          "authorize hook; restrictions are NOT enforced. Install " +
          "createRestrictionsPlugin({ config }) from " +
          "@drakkar.software/starfish-restrictions.",
      )
    }
  }

  // Apply middleware
  if (opts.cors) {
    const corsConfig = typeof opts.cors === "boolean" ? {} : opts.cors
    app.use("*", corsMiddleware(corsConfig))
  }
  if (opts.securityHeaders) {
    const shConfig = typeof opts.securityHeaders === "boolean" ? {} : opts.securityHeaders
    app.use("*", securityHeadersMiddleware(shConfig))
  }
  if (opts.requestTimeoutMs) {
    app.use("*", requestTimeoutMiddleware(opts.requestTimeoutMs))
  }

  app.get("/health", (c) => {
    return c.json({ ok: true, ts: Date.now() })
  })

  app.get("/config", async (c) => {
    const cfg = opts.configEndpoint
    if (!cfg) return c.notFound()

    let callerRoles: string[] = []
    if (cfg.auth === "role-filtered") {
      try {
        const result = await opts.roleResolver(c)
        callerRoles = result.roles
      } catch (e) {
        console.error("[Starfish] /config: roleResolver failed:", e)
        // return empty collections rather than 5xx
      }
    }

    const isVisible = (col: CollectionConfig): boolean => {
      if (cfg.auth === "public") return true
      return (
        col.readRoles.some((r) => callerRoles.includes(r)) ||
        col.writeRoles.some((r) => callerRoles.includes(r))
      )
    }

    const response: ConfigResponse = {
      collections: config.collections.filter(isVisible).map(toCollectionClientInfo),
    }
    if (config.namespaces) {
      response.namespaces = Object.fromEntries(
        Object.entries(config.namespaces).map(([ns, nsCfg]) => [
          ns,
          { collections: nsCfg.collections.filter(isVisible).map(toCollectionClientInfo) },
        ]),
      )
    }
    return c.json(response)
  })

  registerCollectionsOnApp(app, config.collections, opts)

  // Batch pull endpoint: GET /batch/pull?collections=col1,col2
  app.get("/batch/pull", createBatchPullHandler(config.collections, opts))

  // Namespace sub-routers: GET /{ns}/pull/... and POST /{ns}/push/...
  if (config.namespaces) {
    for (const [nsName, nsConfig] of Object.entries(config.namespaces)) {
      mountNamespace(app, nsName, nsConfig, opts)
    }
  }

  return app
}
