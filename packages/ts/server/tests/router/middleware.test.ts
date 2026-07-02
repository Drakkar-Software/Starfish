import { describe, it, expect } from "vitest"
import { Hono } from "hono"
import {
  corsMiddleware,
  securityHeadersMiddleware,
  requestTimeoutMiddleware,
  RateLimiter,
  checkRateLimiters,
} from "../../src/router/middleware.js"

describe("corsMiddleware", () => {
  it("adds CORS headers to responses", async () => {
    const app = new Hono()
    app.use("*", corsMiddleware())
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.status).toBe(200)
    expect(res.headers.get("access-control-allow-origin")).toBe("*")
  })

  it("handles OPTIONS preflight", async () => {
    const app = new Hono()
    app.use("*", corsMiddleware({ origin: "https://example.com" }))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test", {
      method: "OPTIONS",
      headers: { Origin: "https://example.com" },
    })
    expect(res.status).toBe(204)
    expect(res.headers.get("access-control-allow-origin")).toBe("https://example.com")
    expect(res.headers.get("access-control-allow-methods")).toBeTruthy()
  })

  it("respects origin array", async () => {
    const app = new Hono()
    app.use("*", corsMiddleware({ origin: ["https://a.com", "https://b.com"] }))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test", {
      headers: { Origin: "https://b.com" },
    })
    expect(res.headers.get("access-control-allow-origin")).toBe("https://b.com")
  })

  it("sets credentials header when enabled with specific origin", async () => {
    const app = new Hono()
    app.use("*", corsMiddleware({ origin: "https://example.com", credentials: true }))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.headers.get("access-control-allow-credentials")).toBe("true")
  })

  it("throws when credentials + wildcard origin", () => {
    expect(() => corsMiddleware({ credentials: true })).toThrow("credentials cannot be used with wildcard")
  })
})

describe("securityHeadersMiddleware", () => {
  it("adds default security headers", async () => {
    const app = new Hono()
    app.use("*", securityHeadersMiddleware())
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.headers.get("x-content-type-options")).toBe("nosniff")
    expect(res.headers.get("x-frame-options")).toBe("DENY")
    expect(res.headers.get("strict-transport-security")).toBe(
      "max-age=31536000; includeSubDomains",
    )
    expect(res.headers.get("x-xss-protection")).toBe("1; mode=block")
    expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin")
  })

  it("allows disabling individual headers", async () => {
    const app = new Hono()
    app.use("*", securityHeadersMiddleware({
      frameOptions: false,
      xssProtection: false,
    }))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.headers.get("x-content-type-options")).toBe("nosniff")
    expect(res.headers.get("x-frame-options")).toBeNull()
    expect(res.headers.get("x-xss-protection")).toBeNull()
  })

  it("allows custom header values", async () => {
    const app = new Hono()
    app.use("*", securityHeadersMiddleware({
      frameOptions: "SAMEORIGIN",
    }))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.headers.get("x-frame-options")).toBe("SAMEORIGIN")
  })
})

describe("requestTimeoutMiddleware", () => {
  it("allows fast requests through", async () => {
    const app = new Hono()
    app.use("*", requestTimeoutMiddleware(5000))
    app.get("/test", (c) => c.json({ ok: true }))

    const res = await app.request("/test")
    expect(res.status).toBe(200)
  })

  it("returns 408 for slow requests", async () => {
    const app = new Hono()
    app.use("*", requestTimeoutMiddleware(50))
    app.get("/slow", async (c) => {
      await new Promise((r) => setTimeout(r, 200))
      return c.json({ ok: true })
    })

    const res = await app.request("/slow")
    expect(res.status).toBe(408)
    const body = await res.json()
    expect(body.error).toBe("Request timeout")
  })
})

describe("RateLimiter", () => {
  it("allows up to the limit then rejects the next request", async () => {
    const rl = new RateLimiter(60_000, 3)
    expect(await rl.check("u")).toBeNull()
    expect(await rl.check("u")).toBeNull()
    expect(await rl.check("u")).toBeNull()
    expect((await rl.check("u"))?.status).toBe(429) // 4th over the limit of 3
  })

  it("isolates counters per bucket key", async () => {
    const rl = new RateLimiter(60_000, 1)
    expect(await rl.check("a")).toBeNull()
    expect((await rl.check("a"))?.status).toBe(429)
    expect(await rl.check("b")).toBeNull() // a different key is unaffected
  })

  it("keys by identity → resolved socket IP → anonymous, ignoring XFF by default", async () => {
    // Default trustedProxyHops=0: the client-controlled X-Forwarded-For header is NOT
    // trusted, so bucketing falls back to the runtime socket/peer IP (or a shared
    // "anonymous" bucket). Identical precedence to the Python limiter.
    const rl = new RateLimiter(60_000, 1)
    expect(await rl.check("user-1", "1.2.3.4", "5.6.7.8")).toBeNull() // identity wins
    expect((await rl.check("user-1", "9.9.9.9", "8.8.8.8"))?.status).toBe(429) // same identity bucket
    expect(await rl.check(null, null, "3.3.3.3")).toBeNull() // socket IP when no identity
    expect((await rl.check(null, "9.9.9.9", "3.3.3.3"))?.status).toBe(429) // XFF ignored → same socket bucket
    expect(await rl.check(null, null, null)).toBeNull() // shared anonymous fallback
    expect((await rl.check(null, "7.7.7.7", null))?.status).toBe(429) // spoofed XFF → still anonymous
  })

  it("with default settings, a fresh spoofed leftmost X-Forwarded-For does not create a new bucket", async () => {
    // The bypass this fix closes: without a trusted-proxy config, an attacker who
    // rotates X-Forwarded-For must not each time land in a brand-new bucket and so
    // escape the limit. No socket IP (Hono) → all collapse to the "anonymous" bucket.
    const rl = new RateLimiter(60_000, 1)
    expect(await rl.check(null, "1.1.1.1", null)).toBeNull()
    expect((await rl.check(null, "2.2.2.2", null))?.status).toBe(429) // spoofed XFF, same anonymous bucket
    expect((await rl.check(null, "3.3.3.3", null))?.status).toBe(429)

    // With a socket IP present, rotating XFF still maps to the one socket bucket.
    const rl2 = new RateLimiter(60_000, 1)
    expect(await rl2.check(null, "1.1.1.1", "9.9.9.9")).toBeNull()
    expect((await rl2.check(null, "2.2.2.2", "9.9.9.9"))?.status).toBe(429) // same socket peer
  })

  it("trustedProxyHops picks the Nth-from-right X-Forwarded-For entry", async () => {
    // One trusted proxy: the real client is the rightmost XFF entry; a spoofed
    // leftmost entry cannot change the bucket.
    const rl = new RateLimiter(60_000, 1, 10_000, "ip", { trustedProxyHops: 1 })
    expect(await rl.check(null, "1.1.1.1, 9.9.9.9", null)).toBeNull() // client = "9.9.9.9"
    expect((await rl.check(null, "8.8.8.8, 9.9.9.9", null))?.status).toBe(429) // spoofed leftmost, still "9.9.9.9"
    expect(await rl.check(null, "8.8.8.8, 7.7.7.7", null)).toBeNull() // different real client "7.7.7.7"

    // Two trusted proxies: the client is the 2nd entry from the right.
    const rl2 = new RateLimiter(60_000, 1, 10_000, "ip", { trustedProxyHops: 2 })
    expect(await rl2.check(null, "5.5.5.5, 6.6.6.6, 7.7.7.7", null)).toBeNull() // client = "6.6.6.6"
    expect((await rl2.check(null, "0.0.0.0, 6.6.6.6, 8.8.8.8", null))?.status).toBe(429) // still "6.6.6.6"

    // XFF shorter than the hop count → not trusted; fall back to the socket peer.
    const rl3 = new RateLimiter(60_000, 1, 10_000, "ip", { trustedProxyHops: 2 })
    expect(await rl3.check(null, "1.1.1.1", "9.9.9.9")).toBeNull() // 1 hop < 2 → socket "9.9.9.9"
    expect((await rl3.check(null, "2.2.2.2", "9.9.9.9"))?.status).toBe(429) // same socket peer
  })

  it('bucketMode "ip" ignores identity and keys by IP (via a trusted proxy hop)', async () => {
    // Two different identities sharing one IP collapse into one bucket; identity is
    // not consulted at all in "ip" mode. Mirrors the Python twin. trustedProxyHops=1
    // makes the (single-entry) XFF the trusted client IP.
    const rl = new RateLimiter(60_000, 1, 10_000, "ip", { trustedProxyHops: 1 })
    expect(await rl.check("alice", "1.2.3.4", null)).toBeNull()
    expect((await rl.check("bob", "1.2.3.4", null))?.status).toBe(429) // same IP bucket, different identity
    expect(await rl.check("carol", "9.9.9.9", null)).toBeNull() // different IP, fresh bucket
  })

  it('bucketMode "ip" falls back to client IP then anonymous', async () => {
    const rl = new RateLimiter(60_000, 1, 10_000, "ip")
    expect(await rl.check("alice", null, "5.5.5.5")).toBeNull() // client IP when no XFF
    expect((await rl.check("bob", null, "5.5.5.5"))?.status).toBe(429)
    expect(await rl.check("alice", null, null)).toBeNull() // no IP signal at all → anonymous
    expect((await rl.check("bob", null, null))?.status).toBe(429) // shared anonymous bucket
  })

  it('bucketMode "identity+ip" keys by the (identity, ip) pair', async () => {
    // One budget per distinct (identity, ip) combination; changing either dimension
    // yields a fresh bucket. Mirrors the Python twin. trustedProxyHops=1 makes the
    // (single-entry) XFF the trusted client IP.
    const rl = new RateLimiter(60_000, 1, 10_000, "identity+ip", { trustedProxyHops: 1 })
    expect(await rl.check("alice", "1.1.1.1", null)).toBeNull()
    expect((await rl.check("alice", "1.1.1.1", null))?.status).toBe(429) // same pair exhausted
    expect(await rl.check("alice", "2.2.2.2", null)).toBeNull() // same identity, different ip
    expect(await rl.check("bob", "1.1.1.1", null)).toBeNull() // same ip, different identity
  })
})

describe("checkRateLimiters", () => {
  it("returns null when the list is empty (unmetered)", async () => {
    expect(await checkRateLimiters([], "u", null)).toBeNull()
  })

  it("rejects if EITHER an identity or an ip limiter trips (two-independent)", async () => {
    // identity: 5/window, ip: 1/window. Same identity from two IPs. trustedProxyHops=1
    // makes the (single-entry) XFF the trusted client IP for the ip limiter.
    const idLimiter = new RateLimiter(60_000, 5, 10_000, "identity")
    const ipLimiter = new RateLimiter(60_000, 1, 10_000, "ip", { trustedProxyHops: 1 })
    const limiters = [idLimiter, ipLimiter]

    // First request from ip A: both ok.
    expect(await checkRateLimiters(limiters, "alice", "1.1.1.1")).toBeNull()
    // Second request, same identity, same ip A: ip limiter (cap 1) trips → 429.
    expect((await checkRateLimiters(limiters, "alice", "1.1.1.1"))?.status).toBe(429)
    // Same identity from a fresh ip B: ip ok, but identity counter keeps climbing.
    expect(await checkRateLimiters(limiters, "alice", "2.2.2.2")).toBeNull() // identity #3 of 5
    expect(await checkRateLimiters(limiters, "alice", "3.3.3.3")).toBeNull() // identity #4
    expect(await checkRateLimiters(limiters, "alice", "4.4.4.4")).toBeNull() // identity #5
    // identity counter now exhausted (every call increments it, even rejected ones).
    expect((await checkRateLimiters(limiters, "alice", "5.5.5.5"))?.status).toBe(429)
  })
})
