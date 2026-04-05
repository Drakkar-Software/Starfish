import { describe, it, expect } from "vitest"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { MemoryQueue } from "../../src/queue/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"
import { configurePlatform } from "@drakkarsoftware/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeConfig(overrides: Partial<SyncConfig> = {}): SyncConfig {
  return {
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
    ...overrides,
  }
}

function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
  const store = new MemoryObjectStore(new Map())
  const config = overrides.config ?? makeConfig()
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
    ...overrides,
  }
  if (!overrides.store) opts.store = store
  return { app: createSyncRouter(opts), store, opts }
}

describe("health endpoint", () => {
  it("GET /health returns ok", async () => {
    const { app } = makeRouter()
    const res = await app.request("/health")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(true)
    expect(typeof body.ts).toBe("number")
  })
})

describe("pull endpoint", () => {
  it("GET /pull returns empty data for new collection", async () => {
    const { app } = makeRouter()
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({})
    expect(body.hash).toBe("")
    expect(typeof body.timestamp).toBe("number")
  })

  it("GET /pull returns pushed data", async () => {
    const { app } = makeRouter()
    // Push first
    const pushRes = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    expect(pushRes.status).toBe(200)
    const pushBody = await pushRes.json()

    // Then pull
    const pullRes = await app.request("/pull/users/user-1/settings")
    expect(pullRes.status).toBe(200)
    const pullBody = await pullRes.json()
    expect(pullBody.data).toEqual({ theme: "dark" })
    expect(pullBody.hash).toBe(pushBody.hash)
  })

  it("GET /pull with checkpoint filters data", async () => {
    const { app } = makeRouter()
    // First push
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { a: 1, b: 2 }, baseHash: null }),
    })

    const checkpoint = Date.now()
    await new Promise((r) => setTimeout(r, 5))

    // Get current hash
    const pullRes1 = await app.request("/pull/users/user-1/settings")
    const hash = (await pullRes1.json()).hash

    // Second push - change b, add c
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { a: 1, b: 3, c: 4 }, baseHash: hash }),
    })

    const pullRes2 = await app.request(
      `/pull/users/user-1/settings?checkpoint=${checkpoint}`,
    )
    expect(pullRes2.status).toBe(200)
    const body = await pullRes2.json()
    expect(body.data).not.toHaveProperty("a")
    expect(body.data.b).toBe(3)
    expect(body.data.c).toBe(4)
  })

  it("GET /pull with invalid checkpoint returns 400", async () => {
    const { app } = makeRouter()
    const res = await app.request(
      "/pull/users/user-1/settings?checkpoint=abc",
    )
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("Invalid checkpoint")
  })
})

describe("push endpoint", () => {
  it("POST /push succeeds for first push", async () => {
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hash).toHaveLength(64)
    expect(typeof body.timestamp).toBe("number")
  })

  it("POST /push returns 409 on hash mismatch", async () => {
    const { app } = makeRouter()
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 2 }, baseHash: "wrong" }),
    })
    expect(res.status).toBe(409)
    const body = await res.json()
    expect(body.error).toBe("hash_mismatch")
  })

  it("POST /push returns 415 for wrong content-type", async () => {
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "not json",
    })
    expect(res.status).toBe(415)
  })

  it("POST /push returns 400 for non-object body", async () => {
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify("not an object"),
    })
    expect(res.status).toBe(400)
  })

  it("POST /push returns 413 for oversized payload", async () => {
    const { app } = makeRouter({
      config: makeConfig({
        collections: [
          {
            name: "settings",
            storagePath: "users/{identity}/settings",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 10,
            allowedMimeTypes: ["application/json"],
          },
        ],
      }),
    })
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": "999999",
      },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(413)
  })

  it("POST /push sanitizes prototype pollution keys", async () => {
    const { app, store } = makeRouter()
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { safe: 1, __proto__: { evil: true }, constructor: "bad" },
        baseHash: null,
      }),
    })
    const pullRes = await app.request("/pull/users/user-1/settings")
    const body = await pullRes.json()
    expect(body.data).toEqual({ safe: 1 })
    expect(body.data).not.toHaveProperty("__proto__")
    expect(body.data).not.toHaveProperty("constructor")
  })
})

describe("auth", () => {
  it("public collection allows unauthenticated access", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "public-data",
            storagePath: "public/data",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
    })
    const res = await app.request("/pull/public/data")
    expect(res.status).toBe(200)
  })

  it("returns 403 when role not met", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "admin-data",
            storagePath: "admin/data",
            readRoles: ["admin"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["viewer"] }),
    })
    const res = await app.request("/pull/admin/data")
    expect(res.status).toBe(403)
  })

  it("returns 401 when auth fails", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "data",
            storagePath: "data",
            readRoles: ["admin"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
      roleResolver: async () => {
        throw new Error("auth failed")
      },
    })
    const res = await app.request("/pull/data")
    expect(res.status).toBe(401)
  })

  it("self role grants access to own identity path", async () => {
    const { app } = makeRouter({
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
    })
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
  })

  it("self role denies access to other identity path", async () => {
    const { app } = makeRouter({
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
    })
    const res = await app.request("/pull/users/user-2/settings")
    expect(res.status).toBe(403)
  })
})

describe("path validation", () => {
  it("rejects invalid path segments", async () => {
    const { app } = makeRouter()
    const res = await app.request("/pull/users/user 1/settings")
    // Hono may 404 for unmatched routes
    expect([400, 404]).toContain(res.status)
  })
})

describe("read-only / write-only", () => {
  it("pullOnly collection rejects push", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "readonly",
            storagePath: "users/{identity}/readonly",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            pullOnly: true,
          },
        ],
      },
    })
    // pullOnly means no push route registered — should 404
    const res = await app.request("/push/users/user-1/readonly", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(404)
  })

  it("pushOnly collection rejects pull", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "writeonly",
            storagePath: "users/{identity}/writeonly",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            pushOnly: true,
          },
        ],
      },
    })
    // pushOnly means no pull route registered — should 404
    const res = await app.request("/pull/users/user-1/writeonly")
    expect(res.status).toBe(404)
  })
})

describe("queue events", () => {
  it("publishes event after successful push", async () => {
    const queue = new MemoryQueue()
    const { app } = makeRouter({
      queue,
      config: {
        version: 1,
        collections: [
          {
            name: "events",
            storagePath: "users/{identity}/events",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            queue: { includeParams: true },
          },
        ],
      },
    })

    await app.request("/push/users/user-1/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    expect(queue.messages).toHaveLength(1)
    const [subject, payload] = queue.messages[0]!
    expect(subject).toBe("events")
    const msg = JSON.parse(new TextDecoder().decode(payload))
    expect(msg.collection).toBe("events")
    expect(msg.hash).toHaveLength(64)
    expect(msg.params).toEqual({ identity: "user-1" })
  })
})

describe("cache control", () => {
  it("sets Cache-Control header when cacheDurationMs is set", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "cached",
            storagePath: "users/{identity}/cached",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            cacheDurationMs: 30000,
          },
        ],
      },
    })
    const res = await app.request("/pull/users/user-1/cached")
    expect(res.status).toBe(200)
    expect(res.headers.get("cache-control")).toBe("private, max-age=30")
  })
})

describe("bundled collections", () => {
  it("bundle pull returns all collections", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "prefs",
            storagePath: "users/{identity}/data",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "identity",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
          {
            name: "profile",
            storagePath: "users/{identity}/data",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "identity",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
        ],
      },
      encryptionSecret: "test-secret",
    })

    const res = await app.request("/pull/users/user-1/data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toBeDefined()
    expect(body.collections.prefs).toBeDefined()
    expect(body.collections.profile).toBeDefined()
    expect(typeof body.timestamp).toBe("number")
  })

  it("bundle push to individual collection", async () => {
    const { app } = makeRouter({
      config: {
        version: 1,
        collections: [
          {
            name: "prefs",
            storagePath: "users/{identity}/data",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "identity",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
        ],
      },
      encryptionSecret: "test-secret",
    })

    const res = await app.request("/push/users/user-1/data/prefs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { color: "blue" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hash).toHaveLength(64)
  })
})
