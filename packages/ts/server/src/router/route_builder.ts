import { Hono } from "hono"
import * as crypto from "node:crypto"
import type { AbstractObjectStore } from "../storage/base.js"
import type { SyncConfig, CollectionConfig, CollectionRateLimitConfig } from "../config/schema.js"
import { EncryptedObjectStore } from "../encryption/encrypted_store.js"
import { pull } from "../protocol/pull.js"
import {
  handleSyncPull,
  handleSyncPush,
  validatePathSegment,
  parseCheckpoint,
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
  CONTENT_TYPE_JSON,
} from "../constants.js"

export interface AuthResult {
  identity: string
  roles: string[]
}

export type RoleResolver = (request: Request) => Promise<AuthResult>
export type RoleEnricher = (
  auth: AuthResult,
  params: Record<string, string>,
) => Promise<string[]>

export interface SyncRouterOptions {
  store: AbstractObjectStore
  config: SyncConfig
  roleResolver: RoleResolver
  roleEnricher?: RoleEnricher
  encryptionSecret?: string
  serverEncryptionSecret?: string
  serverIdentity?: string
  identityEncryptionInfo?: string
  serverEncryptionInfo?: string
  signatureVerifier?: SignatureVerifier
  roleResolverTimeout?: number
  /** @internal Cached server-encryption store, lazily created. */
  _serverEncryptedStore?: AbstractObjectStore
}

function toRoutePath(action: string, storagePath: string): string {
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

function validateAllParams(params: Record<string, string>): boolean {
  return Object.values(params).every(validatePathSegment)
}


async function checkAuth(
  col: CollectionConfig,
  operation: string,
  request: Request,
  params: Record<string, string>,
  opts: SyncRouterOptions,
): Promise<{ identity: string | null; error: Response | null }> {
  const requiredRoles =
    operation === OP_READ ? (col.readRoles ?? []) : (col.writeRoles ?? [])

  if (requiredRoles.includes(ROLE_PUBLIC)) {
    return { identity: null, error: null }
  }

  let auth: AuthResult
  try {
    const timeout = opts.roleResolverTimeout ?? 5000
    auth = await Promise.race([
      opts.roleResolver(request),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeout),
      ),
    ])
  } catch (err) {
    const msg = err instanceof Error && err.message === "timeout" ? "timeout" : "auth"
    const status = msg === "timeout" ? 503 : 401
    return {
      identity: null,
      error: Response.json({ error: "Unauthorized" }, { status }),
    }
  }

  const effectiveRoles = new Set(auth.roles)

  if (col.storagePath.includes(IDENTITY_PARAM)) {
    if (params[IDENTITY_KEY] === auth.identity) {
      effectiveRoles.add(ROLE_SELF)
    }
  }

  if (opts.roleEnricher) {
    const extra = await opts.roleEnricher(auth, params)
    for (const r of extra) effectiveRoles.add(r)
  }

  const hasAccess = requiredRoles.some((r) => effectiveRoles.has(r))
  if (!hasAccess) {
    return {
      identity: auth.identity,
      error: Response.json({ error: "Forbidden" }, { status: 403 }),
    }
  }

  return { identity: auth.identity, error: null }
}

function resolveStore(
  col: CollectionConfig,
  baseStore: AbstractObjectStore,
  params: Record<string, string>,
  identity: string | null,
  opts: SyncRouterOptions,
): AbstractObjectStore {
  if (col.encryption === ENCRYPTION_IDENTITY) {
    if (!opts.encryptionSecret) {
      throw new Error(`Collection "${col.name}" requires encryptionSecret`)
    }
    const salt = identity || params[IDENTITY_KEY] || ""
    return new EncryptedObjectStore(
      baseStore,
      opts.encryptionSecret,
      salt,
      opts.identityEncryptionInfo || HKDF_INFO_IDENTITY,
    )
  }
  if (col.encryption === ENCRYPTION_SERVER) {
    if (!opts._serverEncryptedStore) {
      if (!opts.serverEncryptionSecret) {
        throw new Error(`Collection "${col.name}" requires serverEncryptionSecret`)
      }
      if (!opts.serverIdentity) {
        throw new Error(`Collection "${col.name}" requires serverIdentity`)
      }
      opts._serverEncryptedStore = new EncryptedObjectStore(
        baseStore,
        opts.serverEncryptionSecret,
        opts.serverIdentity,
        opts.serverEncryptionInfo || HKDF_INFO_SERVER,
      )
    }
    return opts._serverEncryptedStore
  }
  return baseStore
}

function buildRateLimiter(
  colRl: CollectionRateLimitConfig | boolean | undefined,
  opts: SyncRouterOptions,
): RateLimiter | null {
  if (colRl == null || !opts.config.rateLimit) return null
  if (colRl === false) return null
  const globalRl = opts.config.rateLimit
  const resolved = colRl === true ? {} : colRl
  return new RateLimiter(
    resolved.windowMs ?? globalRl.windowMs ?? 60_000,
    resolved.maxRequests ?? globalRl.maxRequests ?? 100,
  )
}

function checkPushGuards(
  request: Request,
  col: CollectionConfig,
  identity: string | null,
  rateLimiter: RateLimiter | null,
): Response | null {
  const contentLength = request.headers.get("content-length")
  if (col.maxBodyBytes) {
    const limitError = checkBodyLimit(contentLength, col.maxBodyBytes)
    if (limitError) return limitError
  }
  if (rateLimiter) {
    const rateError = rateLimiter.check(identity, request)
    if (rateError) return rateError
  }
  return null
}

async function runPush(
  request: Request,
  col: CollectionConfig,
  params: Record<string, string>,
  documentKey: string,
  identity: string | null,
  rateLimiter: RateLimiter | null,
  opts: SyncRouterOptions,
): Promise<Response> {
  const guardError = checkPushGuards(request, col, identity, rateLimiter)
  if (guardError) return guardError

  const contentType = request.headers.get("content-type") ?? ""
  if (!contentType.includes(CONTENT_TYPE_JSON)) {
    return Response.json(
      { error: "Content-Type must be application/json" },
      { status: 415 },
    )
  }

  let body: Record<string, unknown>
  try {
    body = await request.json()
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return Response.json({ error: "Body must be a JSON object" }, { status: 400 })
  }

  const store = resolveStore(col, opts.store, params, identity, opts)
  const isClientEncrypted =
    Boolean(col.clientEncrypted) || col.encryption === ENCRYPTION_DELEGATED
  return handleSyncPush({
    documentKey,
    store,
    body,
    identity,
    verifySignature: opts.signatureVerifier,
    skipTimestamps: isClientEncrypted,
  })
}

async function runBinaryPush(
  request: Request,
  col: CollectionConfig,
  documentKey: string,
  identity: string | null,
  rateLimiter: RateLimiter | null,
  opts: SyncRouterOptions,
): Promise<Response> {
  const guardError = checkPushGuards(request, col, identity, rateLimiter)
  if (guardError) return guardError

  const contentType = request.headers.get("content-type") ?? ""
  if (!matchesAllowedMime(contentType, col.allowedMimeTypes ?? [])) {
    return Response.json(
      {
        error: `Content-Type '${contentType}' is not allowed. Allowed: ${JSON.stringify(col.allowedMimeTypes)}`,
      },
      { status: 415 },
    )
  }

  const body = Buffer.from(await request.arrayBuffer())
  const contentHash = crypto.createHash("sha256").update(body).digest("hex")

  const mediaType = contentType.split(";")[0].trim()
  await opts.store.putBytes(documentKey, body, { contentType: mediaType })

  return Response.json({ hash: contentHash })
}

function addCollectionRoutes(
  app: Hono,
  col: CollectionConfig,
  opts: SyncRouterOptions,
): void {
  const storagePath = col.storagePath

  if (!col.pushOnly) {
    const pullPath = toRoutePath(ACTION_PULL, storagePath)

    app.get(pullPath, async (c) => {
      const params = c.req.param() as Record<string, string>
      if (!validateAllParams(params)) {
        return Response.json({ error: "Invalid path parameter" }, { status: 400 })
      }

      const { identity, error } = await checkAuth(
        col,
        OP_READ,
        c.req.raw,
        params,
        opts,
      )
      if (error) return error

      const documentKey = resolveDocumentKey(storagePath, params)

      if (!isJsonCollection(col.allowedMimeTypes)) {
        const result = await opts.store.getBytes(documentKey)
        if (!result) return new Response(null, { status: 404 })
        const headers: Record<string, string> = {}
        headers["ETag"] = `"${crypto.createHash("sha256").update(result.data).digest("hex")}"`
        if (col.cacheDurationMs != null) {
          const maxAge = Math.floor(col.cacheDurationMs / 1000)
          headers["Cache-Control"] =
            (col.readRoles ?? []).includes(ROLE_PUBLIC)
              ? `max-age=${maxAge}`
              : `private, max-age=${maxAge}`
        }
        return new Response(new Uint8Array(result.data), {
          status: 200,
          headers: { ...headers, "Content-Type": result.contentType },
        })
      }

      const store = resolveStore(col, opts.store, params, identity, opts)
      const checkpointParam = new URL(c.req.url).searchParams.get(QUERY_CHECKPOINT)
      const isClientEncrypted =
        Boolean(col.clientEncrypted) || col.encryption === ENCRYPTION_DELEGATED

      return handleSyncPull({
        documentKey,
        store,
        checkpointParam,
        forceFullFetch: Boolean(col.forceFullFetch),
        clientEncrypted: isClientEncrypted,
        cacheDurationMs: col.cacheDurationMs,
        isPublic: (col.readRoles ?? []).includes(ROLE_PUBLIC),
      })
    })
  }

  if (!col.pullOnly) {
    const pushPath = toRoutePath(ACTION_PUSH, storagePath)
    const rateLimiter = buildRateLimiter(col.rateLimit, opts)

    app.post(pushPath, async (c) => {
      const params = c.req.param() as Record<string, string>
      if (!validateAllParams(params)) {
        return Response.json({ error: "Invalid path parameter" }, { status: 400 })
      }

      const { identity, error } = await checkAuth(
        col,
        OP_WRITE,
        c.req.raw,
        params,
        opts,
      )
      if (error) return error

      const documentKey = resolveDocumentKey(storagePath, params)

      if (!isJsonCollection(col.allowedMimeTypes)) {
        return runBinaryPush(c.req.raw, col, documentKey, identity, rateLimiter, opts)
      }

      return runPush(c.req.raw, col, params, documentKey, identity, rateLimiter, opts)
    })
  }
}

function addBundledRoutes(
  app: Hono,
  _bundleName: string,
  collections: CollectionConfig[],
  opts: SyncRouterOptions,
): void {
  const storagePath = collections[0].storagePath
  const pullPath = toRoutePath(ACTION_PULL, storagePath)
  const isAnyPublic = collections.some((c) =>
    (c.readRoles ?? []).includes(ROLE_PUBLIC),
  )

  app.get(pullPath, async (c) => {
    const params = c.req.param() as Record<string, string>
    if (!validateAllParams(params)) {
      return Response.json({ error: "Invalid path parameter" }, { status: 400 })
    }

    let identity: string | null = null
    if (!isAnyPublic) {
      const auth = await checkAuth(collections[0], OP_READ, c.req.raw, params, opts)
      if (auth.error) return auth.error
      identity = auth.identity
    }

    const baseKey = resolveDocumentKey(storagePath, params)
    const store = resolveStore(collections[0], opts.store, params, identity, opts)

    const anyClientEncrypted = collections.some(
      (col) => col.clientEncrypted || col.encryption === ENCRYPTION_DELEGATED,
    )
    const checkpointParam = new URL(c.req.url).searchParams.get(QUERY_CHECKPOINT)
    let checkpoint = 0
    if (!anyClientEncrypted && checkpointParam != null) {
      const result = parseCheckpoint(checkpointParam)
      if (result instanceof Response) return result
      checkpoint = result
    }

    const pullResults = await Promise.all(
      collections.map((col) => pull(store, `${baseKey}/${col.name}`, checkpoint)),
    )

    const result: Record<string, unknown> = {}
    let latestTimestamp = 0
    for (let i = 0; i < collections.length; i++) {
      const pullResult = pullResults[i]
      result[collections[i].name] = {
        data: pullResult.data,
        hash: pullResult.hash,
      }
      if (pullResult.timestamp > latestTimestamp) {
        latestTimestamp = pullResult.timestamp
      }
    }

    return Response.json({ collections: result, timestamp: latestTimestamp })
  })

  for (const col of collections) {
    if (col.pullOnly) continue

    const pushPath = toRoutePath(ACTION_PUSH, storagePath) + `/${col.name}`
    const rateLimiter = buildRateLimiter(col.rateLimit, opts)

    app.post(pushPath, async (c) => {
      const params = c.req.param() as Record<string, string>
      if (!validateAllParams(params)) {
        return Response.json({ error: "Invalid path parameter" }, { status: 400 })
      }

      const { identity, error } = await checkAuth(
        col,
        OP_WRITE,
        c.req.raw,
        params,
        opts,
      )
      if (error) return error

      const documentKey = `${resolveDocumentKey(storagePath, params)}/${col.name}`
      return runPush(c.req.raw, col, params, documentKey, identity, rateLimiter, opts)
    })
  }
}

export function createSyncRouter(opts: SyncRouterOptions): Hono {
  const app = new Hono()
  const config = opts.config

  app.get("/health", (c) => {
    return c.json({ ok: true, ts: Date.now() })
  })

  const bundles: Record<string, CollectionConfig[]> = {}
  const standalone: CollectionConfig[] = []

  for (const col of config.collections) {
    if (col.bundle) {
      ;(bundles[col.bundle] ??= []).push(col)
    } else {
      standalone.push(col)
    }
  }

  for (const col of standalone) {
    addCollectionRoutes(app, col, opts)
  }

  for (const [bundleName, bundleCollections] of Object.entries(bundles)) {
    addBundledRoutes(app, bundleName, bundleCollections, opts)
  }

  return app
}
