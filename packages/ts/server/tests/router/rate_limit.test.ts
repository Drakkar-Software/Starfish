import { describe, it, expect } from "vitest"
import { createSyncRouter, type AuthResult } from "../../src/router/route_builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"

function buildApp(config: SyncConfig) {
  const store = new MemoryObjectStore({ data: {} })
  const roleResolver = async (request: Request): Promise<AuthResult> => {
    const auth = request.headers.get("authorization")
    if (!auth) throw new Error("No auth")
    return { identity: auth, roles: ["user"] }
  }
  return createSyncRouter({ store, config, roleResolver })
}

describe("rate limiting", () => {
  it("rate limits push requests", async () => {
    const app = buildApp({
      version: 1,
      collections: [
        {
          name: "limited",
          storagePath: "data",
          readRoles: ["public"],
          writeRoles: ["user"],
          rateLimit: { maxRequests: 2 },
        },
      ],
      rateLimit: { windowMs: 60000, maxRequests: 100 },
    })

    const makeReq = () =>
      app.request("/push/data", {
        method: "POST",
        headers: {
          Authorization: "alice",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
      })

    const r1 = await makeReq()
    expect(r1.status).toBe(200)
    const r2 = await makeReq()
    // Second push will conflict (same hash), which is 409 not 429 — that's fine
    // The third should definitely be rate limited
    const r3 = await makeReq()
    expect(r3.status).toBe(429)
  })

  it("does not rate limit pull requests", async () => {
    const app = buildApp({
      version: 1,
      collections: [
        {
          name: "limited",
          storagePath: "data",
          readRoles: ["public"],
          writeRoles: ["user"],
          rateLimit: { maxRequests: 1 },
        },
      ],
      rateLimit: { windowMs: 60000, maxRequests: 100 },
    })

    // Pull is not rate limited (rate limiter is only on push)
    const r1 = await app.request("/pull/data")
    const r2 = await app.request("/pull/data")
    expect(r1.status).toBe(200)
    expect(r2.status).toBe(200)
  })

  it("cache-control header on public collection", async () => {
    const app = buildApp({
      version: 1,
      collections: [
        {
          name: "cached",
          storagePath: "data",
          readRoles: ["public"],
          writeRoles: ["user"],
          cacheDurationMs: 30000,
        },
      ],
    })

    const resp = await app.request("/pull/data")
    expect(resp.status).toBe(200)
    expect(resp.headers.get("cache-control")).toBe("max-age=30")
  })

  it("cache-control header on private collection", async () => {
    const app = buildApp({
      version: 1,
      collections: [
        {
          name: "cached",
          storagePath: "data",
          readRoles: ["user"],
          writeRoles: ["user"],
          cacheDurationMs: 60000,
        },
      ],
    })

    const resp = await app.request("/pull/data", {
      headers: { Authorization: "alice" },
    })
    expect(resp.status).toBe(200)
    expect(resp.headers.get("cache-control")).toBe("private, max-age=60")
  })
})
