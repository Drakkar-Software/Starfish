import { Hono } from "hono"
import type { Context } from "hono"
import { getCrypto } from "@drakkarsoftware/starfish-protocol"
import type { ObjectStore } from "../storage/base.js"
import type {
  SyncConfig,
  CollectionConfig,
  CollectionRateLimitConfig,
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
import { checkBodyLimit, RateLimiter } from "./middleware.js"
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
  IDENTITY_PARAM,
  IDENTITY_KEY,
  QUERY_CHECKPOINT,
  HKDF_INFO_IDENTITY,
  HKDF_INFO_SERVER,
} from "../constants.js"
import type { ReplicaManager } from "../replica/manager.js"
import type { Queue } from "../queue/base.js"

export interface AuthResult {
  identity: string
  roles: string[]
}

export type RoleResolver = (c: Context) => Promise<AuthResult>
export type RoleEnricher = (
  auth: AuthResult,
  params: Record<string, string>,
) => Promise<string[]>

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
}

function toRoutePath(action: string, storagePath: string): string {
  // Convert {param} to :param for Hono routing
  const honoPath = storagePath.replace(/\{(\w+)\}/g, ":$1")
  return `/${action}/${honoPath}`
}

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
): Promise<{ identity: string | null; error: Response | null }> {
  const requiredRoles = operation === OP_READ ? col.readRoles : col.writeRoles

  if (requiredRoles.includes(ROLE_PUBLIC)) {
    return { identity: null, error: null }
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
      return { identity: null, error: c.json({ error: "Unauthorized" }, 503) }
    }
    console.error("[Starfish] roleResolver failed:", e)
    return { identity: null, error: c.json({ error: "Unauthorized" }, 401) }
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
      return { identity: auth.identity, error: c.json({ error: "Authorization error" }, 500) }
    }
  }

  const hasAccess = requiredRoles.some((r) => effectiveRoles.has(r))
  if (!hasAccess) {
    return { identity: auth.identity, error: c.json({ error: "Forbidden" }, 403) }
  }

  return { identity: auth.identity, error: null }
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
): Promise<void> {
  if (!opts.queue || !col.queue || responseStatus !== 200) return
  try {
    const subject = col.queue.topic ?? col.name
    const msg: Record<string, unknown> = {
      collection: col.name,
      hash: responseBody["hash"] ?? "",
      timestamp: responseBody["timestamp"] ?? 0,
    }
    if (col.queue.includeParams && Object.keys(params).length > 0) {
      msg["params"] = params
    }
    await opts.queue.publish(subject, new TextEncoder().encode(JSON.stringify(msg)))
  } catch (e) {
    // Queue errors must not break client writes, but must be visible to operators
    console.error(`[Starfish] Failed to publish queue event for "${col.name}":`, e)
  }
}

async function safePublishEvent(
  opts: SyncRouterOptions,
  col: CollectionConfig,
  response: Response,
  params: Record<string, string>,
): Promise<void> {
  let respBody: Record<string, unknown> | null = null
  try {
    respBody = (await response.clone().json()) as Record<string, unknown>
  } catch (e) {
    console.error("[Starfish] Failed to parse push response for queue event:", e)
    return
  }
  await publishChangeEvent(opts, col, respBody, response.status, params)
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

      const { identity, error } = await checkAuth(col, OP_READ, c, params, opts)
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

  if (!col.pullOnly) {
    const pushPath = toRoutePath(ACTION_PUSH, col.storagePath)
    const rateLimiter = buildRateLimiter(col.rateLimit, opts)

    app.post(pushPath, async (c) => {
      const rawParams = c.req.param()
      const params = extractPathParams(col.storagePath, rawParams)
      if (!validateAllParams(params)) {
        return c.json({ error: "Invalid path parameter" }, 400)
      }

      const { identity, error } = await checkAuth(col, OP_WRITE, c, params, opts)
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

      const documentKey = resolveDocumentKey(col.storagePath, params)

      if (!isJsonCollection(col.allowedMimeTypes)) {
        const response = await runBinaryPush(c, col, documentKey, identity, rateLimiter, opts)
        await safePublishEvent(opts, col, response, params)
        return response
      }

      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts)
      await safePublishEvent(opts, col, response, params)
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
      const response = await runPush(c, col, params, documentKey, identity, rateLimiter, opts)
      await safePublishEvent(opts, col, response, params)
      return response
    })
  }
}

export function createSyncRouter(opts: SyncRouterOptions): Hono {
  const app = new Hono()
  const config = opts.config

  app.get("/health", (c) => {
    return c.json({ ok: true, ts: Date.now() })
  })

  const bundles = new Map<string, CollectionConfig[]>()
  const standalone: CollectionConfig[] = []

  for (const col of config.collections) {
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

  return app
}
