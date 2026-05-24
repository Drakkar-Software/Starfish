import { describe, it, expect } from "vitest"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { jsonDepthWithin, MAX_DOC_DEPTH } from "../../src/router/helpers.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig } from "../../src/config/schema.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
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

  it("GET /pull on a regular collection ignores ?checkpoint= and returns the full document", async () => {
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

    // Incremental sync was removed for regular collections — a stale ?checkpoint=
    // is ignored and the full document is returned (no 400, no field filtering).
    const pullRes2 = await app.request(
      `/pull/users/user-1/settings?checkpoint=${checkpoint}`,
    )
    expect(pullRes2.status).toBe(200)
    const body = await pullRes2.json()
    expect(body.data).toEqual({ a: 1, b: 3, c: 4 })
  })

  it("GET /pull on a regular collection accepts a non-numeric ?checkpoint= (ignored, 200)", async () => {
    const { app } = makeRouter()
    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    const res = await app.request("/pull/users/user-1/settings?checkpoint=abc")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({ theme: "dark" })
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

  it("POST /push rejects a deeply-nested body with 400 (no stack overflow)", async () => {
    const { app } = makeRouter()
    const depth = 5000 // far past MAX_DOC_DEPTH (64) and any safe recursion limit
    const nested = '{"a":'.repeat(depth) + "1" + "}".repeat(depth)
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: `{"data":${nested},"baseHash":null}`,
    })
    expect(res.status).toBe(400)
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
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
          {
            name: "profile",
            storagePath: "users/{identity}/data",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
        ],
      },
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
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            bundle: "userdata",
          },
        ],
      },
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

describe("bundle / batch per-collection authorization + field permissions", () => {
  const jsonHeaders = { "Content-Type": "application/json" }
  const push = (app: ReturnType<typeof createSyncRouter>, path: string, data: unknown) =>
    app.request(path, { method: "POST", headers: jsonHeaders, body: JSON.stringify({ data, baseHash: null }) })

  it("omits a bundle member the caller is not authorized to read", async () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "prefs", storagePath: "users/{identity}/data", readRoles: ["self"], writeRoles: ["self"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "ud" },
        { name: "secret", storagePath: "users/{identity}/data", readRoles: ["admin"], writeRoles: ["admin"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "ud" },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const seed = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "user-1", roles: ["self", "admin"] }) })
    expect((await push(seed, "/push/users/user-1/data/prefs", { color: "blue" })).status).toBe(200)
    expect((await push(seed, "/push/users/user-1/data/secret", { ssn: "123" })).status).toBe(200)

    const selfApp = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "user-1", roles: ["self"] }) })
    const res = await selfApp.request("/pull/users/user-1/data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.prefs?.data).toEqual({ color: "blue" })
    expect(body.collections.secret).toBeUndefined() // caller lacks `admin` → omitted, not leaked
  })

  it("a public bundle member does not make a private sibling public", async () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "pub", storagePath: "shared/data", readRoles: ["public"], writeRoles: ["admin"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "sb" },
        { name: "priv", storagePath: "shared/data", readRoles: ["admin"], writeRoles: ["admin"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "sb" },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const seed = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "admin-1", roles: ["admin"] }) })
    expect((await push(seed, "/push/shared/data/pub", { news: "hi" })).status).toBe(200)
    expect((await push(seed, "/push/shared/data/priv", { secret: "x" })).status).toBe(200)

    const anonApp = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "", roles: ["public"] }) })
    const res = await anonApp.request("/pull/shared/data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.pub?.data).toEqual({ news: "hi" })
    expect(body.collections.priv).toBeUndefined() // private sibling NOT exposed to anonymous
  })

  it("bundle push enforces field-level write permissions", async () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "doc", storagePath: "users/{identity}/data", readRoles: ["self"], writeRoles: ["self"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "fb", fieldPermissions: { adminNote: { writeRoles: ["admin"] } } },
        { name: "other", storagePath: "users/{identity}/data", readRoles: ["self"], writeRoles: ["self"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "fb" },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const selfApp = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "user-1", roles: ["self"] }) })
    const res = await push(selfApp, "/push/users/user-1/data/doc", { adminNote: "x" })
    expect(res.status).toBe(403) // self caller cannot write an admin-only field via the bundle push path
  })

  it("bundle pull strips fields the caller cannot read", async () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "doc", storagePath: "users/{identity}/data", readRoles: ["self"], writeRoles: ["self"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], bundle: "frb", fieldPermissions: { ssn: { readRoles: ["admin"] } } },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const seed = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "user-1", roles: ["self", "admin"] }) })
    expect((await push(seed, "/push/users/user-1/data/doc", { name: "Bob", ssn: "123" })).status).toBe(200)

    const selfApp = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "user-1", roles: ["self"] }) })
    const res = await selfApp.request("/pull/users/user-1/data")
    const body = await res.json()
    expect(body.collections.doc?.data?.name).toBe("Bob")
    expect(body.collections.doc?.data?.ssn).toBeUndefined() // admin-only field stripped on bundle pull
  })

  it("batch pull strips fields the caller cannot read", async () => {
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "notes", storagePath: "shared/notes", readRoles: ["public"], writeRoles: ["admin"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"], fieldPermissions: { ssn: { readRoles: ["admin"] } } },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const seed = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "admin-1", roles: ["admin"] }) })
    expect((await push(seed, "/push/shared/notes", { name: "Bob", ssn: "123" })).status).toBe(200)

    const anonApp = createSyncRouter({ store, config, roleResolver: async () => ({ identity: "", roles: ["public"] }) })
    const res = await anonApp.request("/batch/pull?collections=notes")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.notes?.data?.name).toBe("Bob")
    expect(body.collections.notes?.data?.ssn).toBeUndefined() // admin-only field stripped on batch pull
  })
})

describe("push-through write auditing", () => {
  it("records an audit entry for a proxied (interceptPush respond) write", async () => {
    const records: Array<Record<string, unknown>> = []
    const auditLogger = { record: (e: Record<string, unknown>) => { records.push(e) } }
    // A plugin that proxies the write elsewhere and responds on the route's behalf.
    const proxyPlugin = {
      name: "proxy",
      interceptPush: () => ({ action: "respond" as const, status: 200, body: { hash: "primary-hash", timestamp: 5 } }),
    }
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "data", storagePath: "users/{identity}/data", readRoles: ["self"], writeRoles: ["self"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"] },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      plugins: [proxyPlugin] as unknown as SyncRouterOptions["plugins"],
      auditLogger: auditLogger as unknown as SyncRouterOptions["auditLogger"],
    })
    const res = await app.request("/push/users/user-1/data", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    // The proxied write must be visible in the audit log.
    const pushRecords = records.filter((r) => r.action === "push" && r.collection === "data")
    expect(pushRecords).toHaveLength(1)
    expect(pushRecords[0]!.success).toBe(true)
    expect(pushRecords[0]!.statusCode).toBe(200)
  })

  it("records an audit entry for an auth-denied (403) write", async () => {
    const records: Array<Record<string, unknown>> = []
    const auditLogger = { record: (e: Record<string, unknown>) => { records.push(e) } }
    const config: SyncConfig = {
      version: 1,
      collections: [
        { name: "data", storagePath: "users/{identity}/data", readRoles: ["admin"], writeRoles: ["admin"], encryption: "none", maxBodyBytes: 1_000_000, allowedMimeTypes: ["application/json"] },
      ],
    }
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config,
      roleResolver: async () => ({ identity: "user-1", roles: [] }), // no roles → denied
      auditLogger: auditLogger as unknown as SyncRouterOptions["auditLogger"],
    })
    const res = await app.request("/push/users/user-1/data", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(403)
    const denied = records.filter((r) => r.action === "push" && r.collection === "data")
    expect(denied).toHaveLength(1)
    expect(denied[0]!.success).toBe(false)
    expect(denied[0]!.statusCode).toBe(403)
  })
})

describe("jsonDepthWithin — exact default boundary", () => {
  function nestedObject(levels: number): unknown {
    let node: unknown = 1
    for (let i = 0; i < levels; i++) node = { a: node }
    return node
  }
  function nestedMixed(levels: number): unknown {
    // Alternate object/array so both branches of the iterative walker are hit.
    let node: unknown = 1
    for (let i = 0; i < levels; i++) node = i % 2 === 0 ? { a: node } : [node]
    return node
  }

  it("accepts nesting to exactly MAX_DOC_DEPTH and rejects one level deeper", () => {
    expect(jsonDepthWithin(nestedObject(MAX_DOC_DEPTH))).toBe(true)
    expect(jsonDepthWithin(nestedObject(MAX_DOC_DEPTH + 1))).toBe(false)
    expect(jsonDepthWithin(nestedMixed(MAX_DOC_DEPTH))).toBe(true)
    expect(jsonDepthWithin(nestedMixed(MAX_DOC_DEPTH + 1))).toBe(false)
  })
})

describe("path params — Unicode / homograph / RTL containment", () => {
  // Identical ASCII-only `SAFE_PARAM` to the Python server; validateAllParams runs
  // before auth, so a spoofing identity never reaches the resolver or a storage key.
  it.each([
    ["rtl-override", "‮admin"], // RIGHT-TO-LEFT OVERRIDE (Trojan-source)
    ["cyrillic-homograph", "аdmin"], // Cyrillic 'а' that looks like ASCII 'a'
    ["non-ascii-letter", "café"], // é
    ["dot-leader", "user․settings"], // ONE DOT LEADER, looks like '.'
  ])("rejects a %s identity with 400 before auth", async (_label, ident) => {
    const { app } = makeRouter()
    const res = await app.request(`/pull/users/${encodeURIComponent(ident)}/settings`)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe("Invalid path parameter")
  })
})
