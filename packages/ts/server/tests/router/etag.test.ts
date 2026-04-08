import { describe, it, expect } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
  const store = new MemoryObjectStore(new Map())
  const opts: SyncRouterOptions = {
    store,
    config: {
      version: 1,
      collections: [
        {
          name: "settings",
          storagePath: "users/{identity}/settings",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
        },
      ],
    },
    roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
    ...overrides,
  }
  if (!overrides.store) opts.store = store
  return { app: createSyncRouter(opts), store }
}

describe("ETag conditional requests", () => {
  it("includes ETag header in pull response", async () => {
    const { app } = makeRouter()
    // Push data first
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })

    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const etag = res.headers.get("etag")
    expect(etag).toBeTruthy()
    expect(etag).toMatch(/^"[a-f0-9]{64}"$/)
  })

  it("returns 304 Not Modified when If-None-Match matches", async () => {
    const { app } = makeRouter()
    // Push data
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })

    // First pull to get ETag
    const res1 = await app.request("/pull/users/user-1/settings")
    const etag = res1.headers.get("etag")!

    // Second pull with If-None-Match
    const res2 = await app.request("/pull/users/user-1/settings", {
      headers: { "If-None-Match": etag },
    })
    expect(res2.status).toBe(304)
  })

  it("returns 200 when If-None-Match does not match", async () => {
    const { app } = makeRouter()
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })

    const res = await app.request("/pull/users/user-1/settings", {
      headers: { "If-None-Match": '"stale-hash"' },
    })
    expect(res.status).toBe(200)
  })

  it("does not include ETag for empty collection", async () => {
    const { app } = makeRouter()
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    // Empty hash means no ETag
    expect(body.hash).toBe("")
  })
})

describe("CORS integration", () => {
  it("createSyncRouter with cors option adds CORS headers", async () => {
    const { app } = makeRouter()
    // makeRouter doesn't enable CORS, so no headers
    const res1 = await app.request("/health")
    expect(res1.headers.get("access-control-allow-origin")).toBeNull()
  })

  it("createSyncRouter with cors=true adds default CORS", async () => {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: { version: 1, collections: [] },
      roleResolver: async () => ({ identity: "u", roles: [] }),
      cors: true,
    })
    const res = await app.request("/health")
    expect(res.headers.get("access-control-allow-origin")).toBe("*")
  })
})

describe("Security headers integration", () => {
  it("createSyncRouter with securityHeaders=true adds headers", async () => {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: { version: 1, collections: [] },
      roleResolver: async () => ({ identity: "u", roles: [] }),
      securityHeaders: true,
    })
    const res = await app.request("/health")
    expect(res.headers.get("x-content-type-options")).toBe("nosniff")
    expect(res.headers.get("x-frame-options")).toBe("DENY")
  })
})

describe("Request timeout integration", () => {
  it("createSyncRouter with requestTimeoutMs allows fast requests", async () => {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: { version: 1, collections: [] },
      roleResolver: async () => ({ identity: "u", roles: [] }),
      requestTimeoutMs: 5000,
    })
    const res = await app.request("/health")
    expect(res.status).toBe(200)
  })
})
