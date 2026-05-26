import { Hono } from "hono"
import type { Context } from "hono"
import { getCrypto, computeHash } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import type {
  SyncConfig,
  CollectionConfig,
  CollectionRateLimitConfig,
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
} from "./helpers.js"
import { appendItem } from "../protocol/push.js"
import {
  checkBodyLimit,
  RateLimiter,
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
  APPEND_DEFAULT_FIELD,
  APPEND_MAX_FUTURE_TS_SKEW_MS,
} from "../constants.js"
import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import { dispatchAfterWrite, dispatchBeforePull, dispatchInterceptPush } from "../plugins.js"
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

function resolveDocumentKey(
  template: string,
  params: Record<string, string>,
): string {
  let result = template
  for (const [key, value] of Object.entries(params)) {
    result = result.replace(`{${key}}`, value)
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
}

/**
 * Run the role resolver ONCE and fold in the conditional `self` role and any
 * enricher roles. Returns the effective role set without checking it against a
 * specific collection — callers do that themselves. Extracted so a bundle pull
 * can authorize many collections from a single resolver invocation: the
 * resolver consumes the request nonce (replay protection), so it must run at
 * most once per request.
 */
async function resolveEffectiveRoles(
  c: Context,
  params: Record<string, string>,
  opts: SyncRouterOptions,
  storagePath: string,
): Promise<{ identity: string | null; roles: Set<string>; error: Response | null }> {
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
      return { identity: null, roles: new Set(), error: c.json({ error: "Unauthorized" }, 503) }
    }
    const status = (e as { status?: unknown })?.status
    if (status === 403) {
      return { identity: null, roles: new Set(), error: c.json({ error: "Forbidden" }, 403) }
    }
    if (status === 413) {
      const message = (e instanceof Error && e.message) || "Payload too large"
      return { identity: null, roles: new Set(), error: c.json({ error: message }, 413) }
    }
    console.error("[Starfish] roleResolver failed:", e)
    return { identity: null, roles: new Set(), error: c.json({ error: "Unauthorized" }, 401) }
  }

  // Stash the cap scope (if any) for sibling-read authorization downstream
  // (e.g. the ?withKeyring=1 keyring shortcut in the pull handler). undefined
  // for role-based resolvers that carry no path scope.
  scopePathsByContext.set(c, auth.scopePaths)

  const effectiveRoles = new Set(auth.roles)
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
      return {
        identity: auth.identity,
        roles: effectiveRoles,
        error: c.json({ error: "Authorization error" }, 500),
      }
    }
  }
  return { identity: auth.identity, roles: effectiveRoles, error: null }
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
): Promise<{ identity: string | null; roles: string[]; error: Response | null }> {
  const requiredRoles = operation === OP_READ ? col.readRoles : col.writeRoles

  // A rootOnly collection is never public (enforced at config load), so it must
  // always resolve the caller's roles rather than short-circuit anonymous here.
  if (!col.rootOnly && requiredRoles.includes(ROLE_PUBLIC)) {
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

  const { identity, roles, error } = await resolveEffectiveRoles(c, params, opts, col.storagePath)
  if (error) {
    await auditDenial(identity, error)
    return { identity, roles: [...roles], error }
  }

  const effectiveRolesArray = [...roles]
  if (!isAccessAllowed(col, operation, roles)) {
    const err = c.json({ error: "Forbidden" }, 403)
    await auditDenial(identity, err)
    return { identity, roles: effectiveRolesArray, error: err }
  }

  return { identity, roles: effectiveRolesArray, error: null }
}

function buildRateLimiter(
  colRl: CollectionRateLimitConfig | null | undefined,
  opts: SyncRouterOptions,
): RateLimiter | null {
  if (colRl == null || opts.config.rateLimit == null) return null
  const globalRl = opts.config.rateLimit
  return new RateLimiter(
    colRl.windowMs ?? globalRl.windowMs,
    colRl.maxRequests ?? globalRl.maxRequests,
  )
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
  }
  await dispatchAfterWrite(opts.plugins, event)
}

async function runPush(
  c: Context,
  col: CollectionConfig,
  params: Record<string, string>,
  documentKey: string,
  identity: string | null,
  rateLimiter: RateLimiter | null,
  opts: SyncRouterOptions,
  context?: StoreContext,
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  if (rateLimiter) {
    // Hono has no portable socket IP; pass clientIp=null (direct anonymous traffic
    // shares one bucket). A proxy MUST set X-Forwarded-For for per-client limiting.
    const rateErr = rateLimiter.check(identity ?? null, c.req.header("x-forwarded-for") ?? null)
    if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)
  }

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
    const pushData = bodyObj["data"]
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
    const data = bodyObj["data"]
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
    const item = bodyObj["data"]
    if (item == null || typeof item !== "object" || Array.isArray(item)) {
      return c.json({ error: "Missing or invalid data" }, 400)
    }
    const sanitizedItem = deepSanitize(item as Record<string, unknown>)

    // Optional client-supplied element timestamp (ms since epoch). When present
    // it must be a non-negative integer and strictly greater than the latest
    // stored element's ts (enforced in appendItem); otherwise the server assigns one.
    let providedTs: number | undefined
    const rawTs = bodyObj["ts"]
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
      { maxItems: appendCfg.maxItems, chunkSize: appendCfg.chunkSize },
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
  )
  return c.json(result.body, result.status as any)
}

async function runBinaryPush(
  c: Context,
  col: CollectionConfig,
  documentKey: string,
  identity: string | null,
  rateLimiter: RateLimiter | null,
  opts: SyncRouterOptions,
  context?: StoreContext,
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  if (rateLimiter) {
    // Hono has no portable socket IP; pass clientIp=null (direct anonymous traffic
    // shares one bucket). A proxy MUST set X-Forwarded-For for per-client limiting.
    const rateErr = rateLimiter.check(identity ?? null, c.req.header("x-forwarded-for") ?? null)
    if (rateErr) return c.json({ error: rateErr.error }, rateErr.status as any)
  }

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
            "[Starfish] objectSchema is configured but ajv is not available. " +
            "Install ajv or call setAjv() to provide an instance. Schema validation is DISABLED.",
          )
        }
        return null
      }
      const AjvModule = _require("ajv")
      const Ajv = AjvModule.default || AjvModule
      _ajvInstance = new Ajv()
    } catch (e) {
      if (!_ajvLoadWarned) {
        _ajvLoadWarned = true
        console.error(
          "[Starfish] objectSchema is configured but ajv failed to load. " +
          "Install ajv or call setAjv() to provide an instance. Schema validation is DISABLED.",
          e,
        )
      }
      return null
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
  if (!col.pushOnly) {
    const pullPath = toRoutePath(ACTION_PULL, col.storagePath)

    app.get(pullPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(col.storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error } = await checkAuth(col, OP_READ, c, params, opts)
      if (error) return error

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
        const headers = new Headers()
        headers.set("Content-Type", result.contentType)

        // ETag
        const cr = getCrypto()
        const hashBuf = await cr.subtle.digest("SHA-256", result.body.buffer as ArrayBuffer)
        const etag = Array.from(new Uint8Array(hashBuf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
        headers.set("ETag", `"${etag}"`)

        // ETag conditional request for binary collections
        const ifNoneMatch = c.req.header("if-none-match")
        if (ifNoneMatch === `"${etag}"`) {
          return new Response(null, { status: 304 })
        }

        if (col.cacheDurationMs != null) {
          const maxAge = Math.floor(col.cacheDurationMs / 1000)
          const directive = col.readRoles.includes(ROLE_PUBLIC)
            ? `max-age=${maxAge}`
            : `private, max-age=${maxAge}`
          headers.set("Cache-Control", directive)
        }

        return new Response(result.body.buffer as ArrayBuffer, { status: 200, headers })
      }

      const store = opts.store
      const checkpointParam = c.req.query(QUERY_CHECKPOINT)
      const isPublic = col.readRoles.includes(ROLE_PUBLIC)

      const lastParam = c.req.query("last")
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
        applyFieldReadFilter(pullResult.body["data"], col.fieldPermissions, roles)
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

      const { identity: listIdentity, roles: listRoles, error } = await checkAuth(col, OP_READ, c, params, opts)
      if (error) return error

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
    const rateLimiter = buildRateLimiter(col.rateLimit, opts)

    app.post(pushPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(col.storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error } = await checkAuth(col, OP_WRITE, c, params, opts)
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
        await emitWriteEvent(opts, col, response, params, undefined, namespaceName)
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
          const d = raw["data"]
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

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts, pushCtx)
      await emitWriteEvent(opts, col, response, params, bodyData, namespaceName)
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
    // every member is public, preserving anonymous access to all-public bundles.
    let identity: string | null = null
    let effectiveRoles = new Set<string>()
    if (hasNonPublic) {
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
    const rateLimiter = buildRateLimiter(col.rateLimit, opts)

    app.post(pushPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, roles, error } = await checkAuth(col, OP_WRITE, c, params, opts)
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
          const d = raw["data"]
          if (d !== null && typeof d === "object" && !Array.isArray(d)) {
            bundleBodyData = d as Record<string, unknown>
          }
        } catch {
          // parse failure → bundleBodyData undefined; non-200 guard skips dispatch
        }
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts, bundlePushCtx)
      await emitWriteEvent(opts, col, response, params, bundleBodyData, namespaceName)
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
    // Mirror the Python handler: 400 only when the param itself is absent/empty;
    // once present, empty CSV slots (`,a,,`) are dropped rather than turned into
    // spurious `""` → "Collection not found" entries. An all-empty `,,` therefore
    // resolves to no names and returns `{ collections: {} }`, exactly as Python does.
    const rawCollections = c.req.query("collections")
    if (!rawCollections) {
      return c.json({ error: "Missing collections parameter" }, 400)
    }
    const colNames = rawCollections
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)

    const results: Record<string, Record<string, unknown>> = {}
    for (const name of colNames) {
      const col = collections.find((cc) => cc.name === name)
      if (!col) {
        results[name] = { error: "Collection not found" }
        continue
      }

      // Batch pull resolves storage paths with no params, so a collection whose
      // storagePath has a `{param}` placeholder cannot be addressed here. Report it
      // explicitly instead of reading a synthetic placeholder key that always returns
      // empty (parity with the Python batch handler).
      if (col.storagePath.includes("{")) {
        results[name] = { error: "Collection requires path parameters; not batch-pullable" }
        continue
      }

      const { identity, roles, error: authError } = await checkAuth(col, OP_READ, c, {}, opts)
      if (authError) {
        results[name] = { error: "Forbidden" }
        continue
      }

      try {
        const store = opts.store
        const key = col.storagePath.replace(/\{[^}]+\}/g, "_batch_")
        const batchCtx: StoreContext = {
          collection: col.name,
          params: {},
          identity,
          roles,
          action: ACTION_PULL,
          ...(namespaceName != null && { namespace: namespaceName }),
        }
        const pullResult = await pull(store, key, batchCtx)
        let data = pullResult.data
        // TTL: pull() returns now as its timestamp, so read the stored doc-level
        // write-time to expire stale documents — parity with the standalone pull
        // path (and the Python batch handler). Falls back to the legacy tree.
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
        results[name] = { data, hash: pullResult.hash, timestamp: pullResult.timestamp }
      } catch (e) {
        console.error(`[Starfish] Batch pull failed for collection "${name}":`, e)
        results[name] = { error: "Internal error" }
      }
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
