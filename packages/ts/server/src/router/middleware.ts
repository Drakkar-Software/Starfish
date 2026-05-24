import type { Context, MiddlewareHandler } from "hono"

export function checkBodyLimit(
  contentLength: string | null | undefined,
  maxBytes: number,
): { error: string; status: number } | null {
  if (contentLength == null) return null
  const parsed = parseInt(contentLength, 10)
  if (isNaN(parsed) || parsed < 0) {
    return { error: "Invalid Content-Length", status: 400 }
  }
  if (parsed > maxBytes) {
    return { error: "Payload too large", status: 413 }
  }
  return null
}

interface BucketEntry {
  count: number
  resetAt: number
}

export class RateLimiter {
  private _windowMs: number
  private _maxRequests: number
  private _maxBuckets: number
  private _buckets = new Map<string, BucketEntry>()

  constructor(windowMs: number = 60_000, maxRequests: number = 100, maxBuckets: number = 10_000) {
    this._windowMs = windowMs
    this._maxRequests = maxRequests
    this._maxBuckets = maxBuckets
  }

  check(
    identity: string | null,
    forwardedFor: string | null = null,
    clientIp: string | null = null,
  ): { error: string; status: number } | null {
    // Bucket-key precedence: authenticated identity → first X-Forwarded-For hop →
    // direct client IP → shared "anonymous". Identical to the Python RateLimiter; the
    // only difference is which signals a runtime can supply (Hono has no portable socket
    // IP, so TS callers pass clientIp=null and direct anonymous traffic shares a bucket).
    let bucketKey = identity
    if (!bucketKey && forwardedFor) bucketKey = forwardedFor.split(",")[0]!.trim()
    if (!bucketKey && clientIp) bucketKey = clientIp
    if (!bucketKey) bucketKey = "anonymous"

    const now = Date.now()
    let entry = this._buckets.get(bucketKey)

    if (!entry || entry.resetAt <= now) {
      // Clean up expired entries
      for (const [k, v] of this._buckets) {
        if (v.resetAt <= now) this._buckets.delete(k)
      }
      // Evict oldest if at capacity to prevent unbounded memory growth
      if (this._buckets.size >= this._maxBuckets) {
        const firstKey = this._buckets.keys().next().value
        if (firstKey !== undefined) this._buckets.delete(firstKey)
      }
      entry = { count: 0, resetAt: now + this._windowMs }
      this._buckets.set(bucketKey, entry)
    }

    entry.count += 1

    if (entry.count > this._maxRequests) {
      return { error: "Rate limit exceeded", status: 429 }
    }

    return null
  }
}

// --- CORS ---

export interface CorsConfig {
  origin?: string | string[]
  allowMethods?: string[]
  allowHeaders?: string[]
  exposeHeaders?: string[]
  maxAge?: number
  credentials?: boolean
}

export function corsMiddleware(config: CorsConfig = {}): MiddlewareHandler {
  const origin = config.origin ?? "*"
  const methods = (config.allowMethods ?? ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]).join(", ")
  const allowHeaders = (config.allowHeaders ?? ["Content-Type", "Authorization", "Accept"]).join(", ")
  const exposeHeaders = config.exposeHeaders?.join(", ") ?? ""
  const maxAge = config.maxAge ?? 86400
  const credentials = config.credentials ?? false

  // CORS spec: credentials cannot be used with wildcard origin
  if (credentials && origin === "*") {
    throw new Error("CORS misconfiguration: credentials cannot be used with wildcard origin '*'. Specify explicit origins.")
  }

  function resolveOrigin(requestOrigin: string | undefined): string {
    if (Array.isArray(origin)) {
      return requestOrigin && origin.includes(requestOrigin) ? requestOrigin : origin[0] ?? ""
    }
    return origin
  }

  return async (c: Context, next: () => Promise<void>): Promise<Response | void> => {
    const requestOrigin = c.req.header("origin")
    const resolvedOrigin = resolveOrigin(requestOrigin)

    if (c.req.method === "OPTIONS") {
      const res = new Response(null, { status: 204 })
      res.headers.set("Access-Control-Allow-Origin", resolvedOrigin)
      res.headers.set("Access-Control-Allow-Methods", methods)
      res.headers.set("Access-Control-Allow-Headers", allowHeaders)
      res.headers.set("Access-Control-Max-Age", String(maxAge))
      if (credentials) res.headers.set("Access-Control-Allow-Credentials", "true")
      return res
    }

    await next()

    c.res.headers.set("Access-Control-Allow-Origin", resolvedOrigin)
    if (exposeHeaders) c.res.headers.set("Access-Control-Expose-Headers", exposeHeaders)
    if (credentials) c.res.headers.set("Access-Control-Allow-Credentials", "true")
  }
}

// --- Security Headers ---

export interface SecurityHeadersConfig {
  /** Set to false to disable X-Content-Type-Options. Default: "nosniff" */
  contentTypeOptions?: string | false
  /** Set to false to disable X-Frame-Options. Default: "DENY" */
  frameOptions?: string | false
  /** Set to false to disable Strict-Transport-Security. Default: "max-age=31536000; includeSubDomains" */
  strictTransportSecurity?: string | false
  /** Set to false to disable X-XSS-Protection. Default: "1; mode=block" */
  xssProtection?: string | false
  /** Set to false to disable Referrer-Policy. Default: "strict-origin-when-cross-origin" */
  referrerPolicy?: string | false
}

export function securityHeadersMiddleware(config: SecurityHeadersConfig = {}): MiddlewareHandler {
  const headers: [string, string][] = []

  const cto = config.contentTypeOptions ?? "nosniff"
  if (cto !== false) headers.push(["X-Content-Type-Options", cto])

  const fo = config.frameOptions ?? "DENY"
  if (fo !== false) headers.push(["X-Frame-Options", fo])

  const hsts = config.strictTransportSecurity ?? "max-age=31536000; includeSubDomains"
  if (hsts !== false) headers.push(["Strict-Transport-Security", hsts])

  const xss = config.xssProtection ?? "1; mode=block"
  if (xss !== false) headers.push(["X-XSS-Protection", xss])

  const rp = config.referrerPolicy ?? "strict-origin-when-cross-origin"
  if (rp !== false) headers.push(["Referrer-Policy", rp])

  return async (_c: Context, next: () => Promise<void>) => {
    await next()
    for (const [k, v] of headers) {
      _c.res.headers.set(k, v)
    }
  }
}

// --- Request Timeout ---

export function requestTimeoutMiddleware(timeoutMs: number): MiddlewareHandler {
  return async (c: Context, next: () => Promise<void>) => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("__starfish_timeout__")), timeoutMs)
    })
    try {
      await Promise.race([next(), timeoutPromise])
    } catch (e) {
      if (e instanceof Error && e.message === "__starfish_timeout__") {
        return c.json({ error: "Request timeout" }, 408)
      }
      throw e
    } finally {
      if (timer) clearTimeout(timer)
    }
  }
}
