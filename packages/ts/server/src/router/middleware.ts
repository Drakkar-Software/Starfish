import type { Context, MiddlewareHandler } from "hono"
import { type KVAdapter, createInMemoryKVAdapter } from "../storage/kv-adapter.js"

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

export type RateLimitBucketMode = "identity" | "ip" | "identity+ip"

/** Options for {@link RateLimiter}. */
export interface RateLimiterOptions {
  /** Counter store. Defaults to a per-limiter in-memory adapter (process-local,
   *  preserving the original behavior). Pass a shared/networked adapter (e.g. Garage
   *  K2V) to enforce limits across instances. */
  kv?: KVAdapter
  /** Prefix prepended to every bucket key. REQUIRED when several limiters share one
   *  `kv` (e.g. per collection+action+dimension) so their counters don't collide. */
  keyPrefix?: string
  /** Number of trusted reverse-proxy hops directly in front of this server. When
   *  `0` (the default) the client-controlled `X-Forwarded-For` header is NOT
   *  trusted for bucketing: the bucket falls back to the runtime socket/peer IP
   *  (or a shared `"anonymous"` bucket when the runtime cannot supply one), so a
   *  spoofed XFF cannot mint fresh buckets and slip the limit. When `> 0`, the
   *  real client is taken as the Nth entry FROM THE RIGHT of XFF — each trusted
   *  proxy appends the peer it received the request from, so the rightmost entry
   *  is added by the closest proxy. Set this to the exact number of proxies you
   *  operate; leave it `0` for direct/untrusted ingress. */
  trustedProxyHops?: number
}

export class RateLimiter {
  private _windowMs: number
  private _maxRequests: number
  private _bucketMode: RateLimitBucketMode
  private _kv: KVAdapter
  private _keyPrefix: string
  private _trustedProxyHops: number

  constructor(
    windowMs: number = 60_000,
    maxRequests: number = 100,
    maxBuckets: number = 10_000,
    bucketMode: RateLimitBucketMode = "identity",
    opts: RateLimiterOptions = {},
  ) {
    this._windowMs = windowMs
    this._maxRequests = maxRequests
    this._bucketMode = bucketMode
    // `maxBuckets` bounds the default in-memory store; ignored when a shared `kv` is
    // supplied (that backend owns its own capacity policy / TTL-based bounding).
    this._kv = opts.kv ?? createInMemoryKVAdapter({ maxKeys: maxBuckets })
    this._keyPrefix = opts.keyPrefix ?? ""
    this._trustedProxyHops = opts.trustedProxyHops ?? 0
  }

  /**
   * Resolve the IP component of the bucket key from the (client-controlled)
   * `X-Forwarded-For` header and the runtime socket/peer IP. Identical logic to
   * the Python `RateLimiter._resolve_ip_part`.
   *
   * With `trustedProxyHops === 0` (default) XFF is ignored entirely — a spoofed
   * header cannot create a new bucket. With `N > 0` the Nth-from-right XFF entry
   * (the real client behind N trusted proxies) is used; if the header is shorter
   * than N, it is not trusted and the socket peer is used instead.
   */
  private _resolveIpPart(forwardedFor: string | null, clientIp: string | null): string {
    if (this._trustedProxyHops > 0) {
      const hops = forwardedFor
        ? forwardedFor.split(",").map((h) => h.trim()).filter((h) => h.length > 0)
        : []
      if (hops.length >= this._trustedProxyHops) {
        return hops[hops.length - this._trustedProxyHops]!
      }
      // Fewer hops than expected → the chain is not the trusted shape; fall back
      // to the socket peer (coarse, but not attacker-spoofable).
      return clientIp ?? "anonymous"
    }
    // Default: do NOT trust the client-controlled XFF. Bucket by the runtime
    // socket/peer IP, sharing one "anonymous" bucket when unavailable.
    return clientIp ?? "anonymous"
  }

  async check(
    identity: string | null,
    forwardedFor: string | null = null,
    clientIp: string | null = null,
  ): Promise<{ error: string; status: number } | null> {
    // Bucket-key precedence: in "identity" mode, authenticated identity → resolved
    // IP part → shared "anonymous". In "ip" mode the identity is ignored and
    // bucketing is by the resolved IP only. In "identity+ip" mode the key is the
    // (identity, ip) pair, so one budget is kept per distinct combination. The IP
    // part is derived by `_resolveIpPart`, which by default ignores the spoofable
    // X-Forwarded-For header (see `trustedProxyHops`). Identical to the Python
    // RateLimiter; the only difference is which signals a runtime can supply (Hono
    // has no portable socket IP, so TS callers pass clientIp=null).
    const ipPart = this._resolveIpPart(forwardedFor, clientIp)
    let bucketKey: string
    if (this._bucketMode === "ip") {
      bucketKey = ipPart
    } else if (this._bucketMode === "identity+ip") {
      bucketKey = `${identity ?? "anonymous"}|${ipPart}`
    } else {
      bucketKey = identity ?? ipPart
    }

    const count = await this._kv.increment(this._keyPrefix + bucketKey, this._windowMs)
    if (count > this._maxRequests) {
      return { error: "Rate limit exceeded", status: 429 }
    }
    return null
  }
}

/**
 * Apply a list of rate limiters to one request and return the first 429 error, or
 * null if all pass. A single-counter rule supplies one limiter; a two-independent
 * rule (per-identity AND per-ip) supplies two — the request is rejected if either
 * dimension is over budget. NOTE: every limiter is consulted (each increments its
 * counter) before returning, so the dimensions stay in lock-step regardless of order.
 */
export async function checkRateLimiters(
  limiters: readonly RateLimiter[],
  identity: string | null,
  forwardedFor: string | null = null,
  clientIp: string | null = null,
): Promise<{ error: string; status: number } | null> {
  let firstError: { error: string; status: number } | null = null
  for (const rl of limiters) {
    const err = await rl.check(identity, forwardedFor, clientIp)
    if (err && !firstError) firstError = err
  }
  return firstError
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
