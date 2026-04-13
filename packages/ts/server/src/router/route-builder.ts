import { Hono } from "hono"
import type { Context } from "hono"
import { getCrypto } from "@drakkar.software/starfish-protocol"
import type { ObjectStore } from "../storage/base.js"
import type {
  SyncConfig,
  CollectionConfig,
  CollectionRateLimitConfig,
  EncryptionMode,
  FieldPermission,
  NamespaceConfig,
} from "../config/schema.js"
import { EncryptedObjectStore } from "../encryption/encrypted-store.js"
import { pull } from "../protocol/pull.js"
import {
  handleSyncPull,
  handleSyncPush,
  validatePathSegment,
  deepSanitize,
  type SignatureVerifier,
} from "./helpers.js"
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
import {
  ROLE_PUBLIC,
  ROLE_SELF,
  OP_READ,
  OP_WRITE,
  ENCRYPTION_IDENTITY,
  ENCRYPTION_SERVER,
  ENCRYPTION_DELEGATED,
  ACTION_PULL,
  ACTION_PUSH,
  ACTION_LIST,
  IDENTITY_PARAM,
  IDENTITY_KEY,
  QUERY_CHECKPOINT,
  HKDF_INFO_IDENTITY,
  HKDF_INFO_SERVER,
} from "../constants.js"
import type { ReplicaManager } from "../replica/manager.js"
import type { Queue } from "../queue/base.js"
import type { QueueMessage } from "../queue/message.js"
import type { ServerLogger } from "../logger.js"
import type { AuditLogger, AuditEntry } from "../audit.js"
import { isExpired } from "../ttl.js"

export interface AuthResult {
  identity: string
  roles: string[]
}

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
  queueOnly?: boolean
  clientEncrypted?: boolean
  /** Base64-encoded public key for client-side encryption, if configured. */
  publicKey?: string
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
  encryptionSecret?: string
  serverEncryptionSecret?: string
  serverIdentity?: string
  identityEncryptionInfo?: string
  serverEncryptionInfo?: string
  signatureVerifier?: SignatureVerifier
  replicaManager?: ReplicaManager
  queue?: Queue
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

async function checkAuth(
  col: CollectionConfig,
  operation: string,
  c: Context,
  params: Record<string, string>,
  opts: SyncRouterOptions,
): Promise<{ identity: string | null; roles: string[]; error: Response | null }> {
  const requiredRoles = operation === OP_READ ? col.readRoles : col.writeRoles

  if (requiredRoles.includes(ROLE_PUBLIC)) {
    return { identity: null, roles: [], error: null }
  }

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
      return { identity: null, roles: [], error: c.json({ error: "Unauthorized" }, 503) }
    }
    console.error("[Starfish] roleResolver failed:", e)
    return { identity: null, roles: [], error: c.json({ error: "Unauthorized" }, 401) }
  }

  const effectiveRoles = new Set(auth.roles)

  if (col.storagePath.includes(IDENTITY_PARAM)) {
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
      return { identity: auth.identity, roles: [...effectiveRoles], error: c.json({ error: "Authorization error" }, 500) }
    }
  }

  const effectiveRolesArray = [...effectiveRoles]
  const hasAccess = requiredRoles.some((r) => effectiveRoles.has(r))
  if (!hasAccess) {
    return { identity: auth.identity, roles: effectiveRolesArray, error: c.json({ error: "Forbidden" }, 403) }
  }

  return { identity: auth.identity, roles: effectiveRolesArray, error: null }
}

function resolveStore(
  col: CollectionConfig,
  baseStore: ObjectStore,
  params: Record<string, string>,
  identity: string | null,
  opts: SyncRouterOptions,
): ObjectStore {
  if (col.encryption === ENCRYPTION_IDENTITY) {
    if (!opts.encryptionSecret) {
      throw new Error(`Collection "${col.name}" requires encryptionSecret`)
    }
    const salt = identity ?? params[IDENTITY_KEY] ?? ""
    return new EncryptedObjectStore(
      baseStore,
      opts.encryptionSecret,
      salt,
      opts.identityEncryptionInfo ?? HKDF_INFO_IDENTITY,
    )
  }
  if (col.encryption === ENCRYPTION_SERVER) {
    if (!opts.serverEncryptionSecret) {
      throw new Error(`Collection "${col.name}" requires serverEncryptionSecret`)
    }
    if (!opts.serverIdentity) {
      throw new Error(`Collection "${col.name}" requires serverIdentity`)
    }
    return new EncryptedObjectStore(
      baseStore,
      opts.serverEncryptionSecret,
      opts.serverIdentity,
      opts.serverEncryptionInfo ?? HKDF_INFO_SERVER,
    )
  }
  return baseStore
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

async function publishChangeEvent(
  opts: SyncRouterOptions,
  col: CollectionConfig,
  responseBody: Record<string, unknown>,
  responseStatus: number,
  params: Record<string, string>,
  bodyData?: Record<string, unknown>,
): Promise<void> {
  if (!opts.queue || !col.queue || responseStatus !== 200) return
  try {
    const subject = col.queue.topic ?? col.name
    const msg: QueueMessage = {
      collection: col.name,
      hash: (responseBody["hash"] as string) ?? "",
      timestamp: (responseBody["timestamp"] as number) ?? 0,
    }
    if (col.queue.includeParams && Object.keys(params).length > 0) {
      msg.params = params
    }
    if (col.queue.includeBody && bodyData !== undefined) {
      msg.body = bodyData
    }
    await opts.queue.publish(subject, new TextEncoder().encode(JSON.stringify(msg)))
  } catch (e) {
    // Queue errors must not break client writes, but must be visible to operators
    console.warn(`[Starfish] Failed to publish queue event for "${col.name}":`, e)
  }
}

async function safePublishEvent(
  opts: SyncRouterOptions,
  col: CollectionConfig,
  response: Response,
  params: Record<string, string>,
  bodyData?: Record<string, unknown>,
): Promise<void> {
  let respBody: Record<string, unknown> | null = null
  try {
    respBody = (await response.clone().json()) as Record<string, unknown>
  } catch (e) {
    console.error("[Starfish] Failed to parse push response for queue event:", e)
    return
  }
  await publishChangeEvent(opts, col, respBody, response.status, params, bodyData)
}

async function proxyPushToPrimary(
  col: CollectionConfig,
  c: Context,
  replicaManager: ReplicaManager,
): Promise<Response> {
  const remote = col.remote!
  const primaryUrl = `${remote.url.replace(/\/+$/, "")}${remote.pushPath}`

  const rawBody = await c.req.text()
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...remote.headers,
  }

  try {
    const resp = await fetch(primaryUrl, {
      method: "POST",
      body: rawBody,
      headers,
    })

    if (resp.status === 409) {
      return c.json({ error: "hash_mismatch" }, 409)
    }
    if (!resp.ok) {
      return c.json({ error: `Primary returned ${resp.status}` }, resp.status as any)
    }

    const body = (await resp.json()) as Record<string, unknown>

    // Trigger sync in background (don't await)
    replicaManager.syncNow(col.name).catch((e) => {
      console.error(`[Starfish] Background sync failed for "${col.name}" after proxy push:`, e)
    })

    return c.json(body, resp.status as any)
  } catch (e) {
    return c.json({ error: `Failed to reach primary: ${e}` }, 502)
  }
}

async function runPush(
  c: Context,
  col: CollectionConfig,
  params: Record<string, string>,
  documentKey: string,
  identity: string | null,
  rateLimiter: RateLimiter | null,
  opts: SyncRouterOptions,
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  if (rateLimiter) {
    const rateErr = rateLimiter.check(identity ?? null, {
      get: (name: string) => c.req.header(name) ?? null,
    })
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

  const bodyObj = body as Record<string, unknown>

  // JSON Schema validation
  if (col.objectSchema != null) {
    const data = bodyObj["data"]
    if (data != null && typeof data === "object" && !Array.isArray(data)) {
      const schemaErr = validateObjectSchema(data as Record<string, unknown>, col.objectSchema)
      if (schemaErr) return c.json(schemaErr.body, schemaErr.status as any)
    }
  }

  const store = resolveStore(col, opts.store, params, identity, opts)
  const isClientEncrypted = Boolean(col.clientEncrypted) || col.encryption === ENCRYPTION_DELEGATED
  const result = await handleSyncPush(
    documentKey,
    store,
    bodyObj,
    identity,
    opts.signatureVerifier,
    isClientEncrypted,
    col.queueOnly ?? false,
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
): Promise<Response> {
  const contentLength = c.req.header("content-length")
  const limitErr = checkBodyLimit(contentLength ?? null, col.maxBodyBytes)
  if (limitErr) return c.json({ error: limitErr.error }, limitErr.status as any)

  if (rateLimiter) {
    const rateErr = rateLimiter.check(identity ?? null, {
      get: (name: string) => c.req.header(name) ?? null,
    })
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
  await opts.store.putBytes(documentKey, new Uint8Array(rawBuffer), { contentType: mediaType })

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

      if (col.remote?.writeMode === "push_only") {
        return c.json({ error: "This collection is write-only on this server" }, 405)
      }

      if (
        opts.replicaManager &&
        col.remote &&
        col.remote.syncTriggers.includes("on_pull")
      ) {
        await opts.replicaManager.onPull(col.name)
      }

      const documentKey = resolveDocumentKey(col.storagePath, params)

      // Binary collection: return raw bytes
      if (!isJsonCollection(col.allowedMimeTypes)) {
        if (!opts.store.getBytes) {
          return c.json({ error: "Store does not support binary operations" }, 501)
        }
        const result = await opts.store.getBytes(documentKey)
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

      const store = resolveStore(col, opts.store, params, identity, opts)
      const checkpointParam = c.req.query(QUERY_CHECKPOINT)
      const isClientEncrypted =
        Boolean(col.clientEncrypted) || col.encryption === ENCRYPTION_DELEGATED
      const pullResult = await handleSyncPull(
        documentKey,
        store,
        checkpointParam,
        Boolean(col.forceFullFetch),
        isClientEncrypted,
        col.cacheDurationMs,
        col.readRoles.includes(ROLE_PUBLIC),
      )

      // TTL check: return empty data for expired documents
      if (col.ttlMs != null && pullResult.status === 200) {
        const ts = pullResult.body["timestamp"] as number | undefined
        if (ts && isExpired(ts, col.ttlMs)) {
          pullResult.body = { data: {}, hash: "", timestamp: ts }
        }
      }

      // Field-level read permissions: strip fields the user can't read
      if (col.fieldPermissions && pullResult.status === 200) {
        const data = pullResult.body["data"] as Record<string, unknown> | undefined
        if (data && typeof data === "object") {
          const userRoles = new Set(roles)
          for (const [field, perm] of Object.entries(col.fieldPermissions)) {
            if (perm.readRoles && perm.readRoles.length > 0) {
              const hasAccess = perm.readRoles.some((r) => userRoles.has(r) || r === ROLE_PUBLIC)
              if (!hasAccess) {
                delete data[field]
              }
            }
          }
        }
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
        opts.auditLogger.record({
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

      const { error } = await checkAuth(col, OP_READ, c, params, opts)
      if (error) return error

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
      const keys = await opts.store.listKeys(prefix, { startAfter, limit: limit + 1 })
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

      if (col.remote?.writeMode === "push_through" && opts.replicaManager) {
        return proxyPushToPrimary(col, c, opts.replicaManager)
      }

      if (col.remote?.writeMode === "pull_only") {
        return c.json(
          { error: "This collection is read-only on this server" },
          405,
        )
      }

      // Field-level write permissions: reject writes to restricted fields
      if (col.fieldPermissions && isJsonCollection(col.allowedMimeTypes)) {
        try {
          const rawBody = await c.req.json() as Record<string, unknown>
          const pushData = rawBody["data"] as Record<string, unknown> | undefined
          if (pushData && typeof pushData === "object") {
            const userRoles = new Set(roles)
            for (const [field, perm] of Object.entries(col.fieldPermissions)) {
              if (perm.writeRoles && perm.writeRoles.length > 0 && field in pushData) {
                const hasAccess = perm.writeRoles.some((r) => userRoles.has(r) || r === ROLE_PUBLIC)
                if (!hasAccess) {
                  return c.json({ error: `Field '${field}' is not writable with your roles` }, 403)
                }
              }
            }
          }
        } catch {
          // Body parsing will be handled by the push handler
        }
      }

      const documentKey = resolveDocumentKey(col.storagePath, params)

      if (!isJsonCollection(col.allowedMimeTypes)) {
        const response = await runBinaryPush(c, col, documentKey, identity, rateLimiter, opts)
        await safePublishEvent(opts, col, response, params)
        if (opts.auditLogger) {
          opts.auditLogger.record({ timestamp: Date.now(), action: "push", collection: col.name, identity, documentKey, success: response.status === 200, statusCode: response.status, params })
        }
        return response
      }

      let bodyData: Record<string, unknown> | undefined
      if (col.queue?.includeBody) {
        try {
          const raw = (await c.req.json()) as Record<string, unknown>
          const d = raw["data"]
          if (d !== null && typeof d === "object" && !Array.isArray(d)) {
            bodyData = d as Record<string, unknown>
          } else {
            console.warn(`[Starfish] includeBody enabled for "${col.name}" but request data is not a plain object; body will be omitted from queue message`)
          }
        } catch {
          // JSON parse failed → bodyData stays undefined.
          // runPush will independently re-parse and reject with 400,
          // so no queue event will be published due to the non-200 status guard.
          console.warn(`[Starfish] includeBody: failed to parse request body for queue message on "${col.name}"`)
        }
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts)
      await safePublishEvent(opts, col, response, params, bodyData)
      if (opts.auditLogger) {
        opts.auditLogger.record({ timestamp: Date.now(), action: "push", collection: col.name, identity, documentKey, success: response.status === 200, statusCode: response.status, params })
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
): void {
  const storagePath = collections[0]!.storagePath
  const pullPath = toRoutePath(ACTION_PULL, storagePath)
  const isAnyPublic = collections.some((c) => c.readRoles.includes(ROLE_PUBLIC))

  app.get(pullPath, async (c) => {
    const rawParams = c.req.param()
    const params = extractPathParams(storagePath, rawParams)
    if (!validateAllParams(params)) {
      return c.json({ error: "Invalid path parameter" }, 400)
    }

    let identity: string | null = null
    if (!isAnyPublic) {
      const authResult = await checkAuth(collections[0]!, OP_READ, c, params, opts)
      if (authResult.error) return authResult.error
      identity = authResult.identity
    }

    const baseKey = resolveDocumentKey(storagePath, params)
    const store = resolveStore(collections[0]!, opts.store, params, identity, opts)

    const anyClientEncrypted = collections.some(
      (col) => col.clientEncrypted || col.encryption === ENCRYPTION_DELEGATED,
    )
    const checkpointParam = c.req.query(QUERY_CHECKPOINT)
    let checkpoint = 0
    if (!anyClientEncrypted && checkpointParam != null) {
      const parsed = parseInt(checkpointParam, 10)
      if (isNaN(parsed) || parsed < 0 || String(parsed) !== checkpointParam) {
        return c.json({ error: "Invalid checkpoint" }, 400)
      }
      checkpoint = parsed
    }

    const result: Record<string, Record<string, unknown>> = {}
    let latestTimestamp = 0

    for (const col of collections) {
      const documentKey = `${baseKey}/${col.name}`
      const pullResult = await pull(store, documentKey, checkpoint)
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

      const { identity, error } = await checkAuth(col, OP_WRITE, c, params, opts)
      if (error) return error

      const documentKey = `${resolveDocumentKey(storagePath, params)}/${col.name}`

      let bundleBodyData: Record<string, unknown> | undefined
      if (col.queue?.includeBody) {
        try {
          const raw = (await c.req.json()) as Record<string, unknown>
          const d = raw["data"]
          if (d !== null && typeof d === "object" && !Array.isArray(d)) {
            bundleBodyData = d as Record<string, unknown>
          } else {
            console.warn(`[Starfish] includeBody enabled for "${col.name}" but request data is not a plain object; body will be omitted from queue message`)
          }
        } catch {
          console.warn(`[Starfish] includeBody: failed to parse request body for queue message on "${col.name}"`)
        }
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts)
      await safePublishEvent(opts, col, response, params, bundleBodyData)
      return response
    })
  }
}

function registerCollectionsOnApp(
  app: Hono,
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
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
    addCollectionRoutes(app, col, opts)
  }

  for (const [bundleName, bundleCollections] of bundles) {
    addBundledRoutes(app, bundleName, bundleCollections, opts)
  }
}

function createBatchPullHandler(
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
) {
  return async (c: Context) => {
    const colNames = c.req.query("collections")?.split(",").map((s) => s.trim()) ?? []
    if (colNames.length === 0) {
      return c.json({ error: "Missing collections parameter" }, 400)
    }

    const results: Record<string, Record<string, unknown>> = {}
    for (const name of colNames) {
      const col = collections.find((cc) => cc.name === name)
      if (!col) {
        results[name] = { error: "Collection not found" }
        continue
      }

      const { identity, error: authError } = await checkAuth(col, OP_READ, c, {}, opts)
      if (authError) {
        results[name] = { error: "Forbidden" }
        continue
      }

      try {
        const store = resolveStore(col, opts.store, {}, identity, opts)
        const key = col.storagePath.replace(/\{[^}]+\}/g, "_batch_")
        const pullResult = await pull(store, key, 0)
        results[name] = { data: pullResult.data, hash: pullResult.hash, timestamp: pullResult.timestamp }
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
  registerCollectionsOnApp(nsApp, nsConfig.collections, opts)
  nsApp.get("/batch/pull", createBatchPullHandler(nsConfig.collections, opts))
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
  if (col.queueOnly) info.queueOnly = true
  if (col.clientEncrypted) info.clientEncrypted = true
  if (col.publicKey) info.publicKey = col.publicKey
  if (col.ttlMs != null) info.ttlMs = col.ttlMs
  if (col.forceFullFetch) info.forceFullFetch = true
  return info
}

export function createSyncRouter(opts: SyncRouterOptions): Hono {
  const app = new Hono()
  const config = opts.config

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
      } catch {
        // roleResolver failed — return empty collections rather than 5xx
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
