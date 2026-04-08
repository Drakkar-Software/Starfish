import { describe, it, expect } from "vitest"
import { Hono } from "hono"
import {
  corsMiddleware,
  securityHeadersMiddleware,
  requestTimeoutMiddleware,
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
