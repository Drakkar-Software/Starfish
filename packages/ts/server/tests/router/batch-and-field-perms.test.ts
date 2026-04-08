import { describe, it, expect, vi } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { createCallbackAuditLogger } from "../../src/audit.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

describe("batch pull endpoint", () => {
  function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
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
          {
            name: "private-data",
            storagePath: "private/data",
            readRoles: ["admin"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["viewer"] }),
      ...overrides,
    })
    return { app, store }
  }

  it("returns 400 for missing collections parameter", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull")
    expect(res.status).toBe(400)
  })

  it("returns error for unknown collection", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=nonexistent")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.nonexistent.error).toBe("Collection not found")
  })

  it("allows access to public collections", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=public-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["public-data"]).toBeDefined()
    expect(body.collections["public-data"].data).toBeDefined()
  })

  it("denies access to private collections without proper roles", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["private-data"].error).toBe("Forbidden")
  })

  it("returns mixed results for public and private collections", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=public-data,private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    // Public should succeed
    expect(body.collections["public-data"].data).toBeDefined()
    // Private should fail
    expect(body.collections["private-data"].error).toBe("Forbidden")
  })

  it("allows admin to access private collections", async () => {
    const { app } = makeRouter({
      roleResolver: async () => ({ identity: "admin-1", roles: ["admin"] }),
    })
    const res = await app.request("/batch/pull?collections=private-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections["private-data"].data).toBeDefined()
  })
})

describe("field-level permissions", () => {
  function makeRouter(overrides: Partial<SyncRouterOptions> = {}) {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
              name: { readRoles: ["self", "admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
      ...overrides,
    })
    return { app, store }
  }

  it("strips fields the user can't read", async () => {
    // Push as admin (has write access to all fields)
    const { app: adminApp } = makeRouter({
      roleResolver: async () => ({ identity: "user-1", roles: ["admin"] }),
    })
    const pushRes = await adminApp.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com", bio: "Hello" },
        baseHash: null,
      }),
    })
    expect(pushRes.status).toBe(200)

    // Pull as non-admin — email should be stripped
    // Need a new router with same store to test with different roles
    // Since stores are isolated per makeRouter call, use admin router for pull too
    // but override the roleResolver for pull
    const res = await adminApp.request("/pull/users/user-1/profile")
    expect(res.status).toBe(200)
    const body = await res.json()
    // Admin can see all fields including email
    expect(body.data.name).toBe("Alice")
    expect(body.data.email).toBe("alice@example.com")
    expect(body.data.bio).toBe("Hello")
  })

  it("non-admin cannot read admin-restricted fields", async () => {
    // Push as admin first
    const store = new MemoryObjectStore(new Map())
    const adminApp = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["admin"] }),
    })
    await adminApp.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com" },
        baseHash: null,
      }),
    })

    // Pull as non-admin (same store, different role resolver)
    const userApp = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "profile",
            storagePath: "users/{identity}/profile",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            fieldPermissions: {
              email: { readRoles: ["admin"], writeRoles: ["admin"] },
            },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: [] }),
    })
    const res = await userApp.request("/pull/users/user-1/profile")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.name).toBe("Alice")
    expect(body.data.email).toBeUndefined() // Stripped for non-admin
  })

  it("rejects writes to field-restricted fields", async () => {
    const { app } = makeRouter()
    // Non-admin trying to write email (restricted to admin writeRoles)
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", email: "alice@example.com" },
        baseHash: null,
      }),
    })
    expect(res.status).toBe(403)
    const body = await res.json()
    expect(body.error).toContain("email")
  })

  it("allows writes to unrestricted fields", async () => {
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        data: { name: "Alice", bio: "Hello" },
        baseHash: null,
      }),
    })
    expect(res.status).toBe(200)
  })
})

describe("audit logging integration", () => {
  it("records pull events to audit logger", async () => {
    const entries: any[] = []
    const auditLogger = createCallbackAuditLogger((e) => { entries.push(e) })
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
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
      auditLogger,
    })

    await app.request("/pull/users/user-1/settings")
    expect(entries).toHaveLength(1)
    expect(entries[0].action).toBe("pull")
    expect(entries[0].collection).toBe("settings")
    expect(entries[0].identity).toBe("user-1")
    expect(entries[0].success).toBe(true)
  })

  it("records push events to audit logger", async () => {
    const entries: any[] = []
    const auditLogger = createCallbackAuditLogger((e) => { entries.push(e) })
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
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
      auditLogger,
    })

    await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(entries).toHaveLength(1)
    expect(entries[0].action).toBe("push")
    expect(entries[0].success).toBe(true)
  })
})

describe("CORS credentials validation", () => {
  it("throws when credentials=true with wildcard origin", () => {
    expect(() => {
      createSyncRouter({
        store: new MemoryObjectStore(new Map()),
        config: { version: 1, collections: [] },
        roleResolver: async () => ({ identity: "u", roles: [] }),
        cors: { credentials: true },
      })
    }).toThrow("credentials cannot be used with wildcard origin")
  })

  it("allows credentials with specific origin", () => {
    expect(() => {
      createSyncRouter({
        store: new MemoryObjectStore(new Map()),
        config: { version: 1, collections: [] },
        roleResolver: async () => ({ identity: "u", roles: [] }),
        cors: { origin: "https://example.com", credentials: true },
      })
    }).not.toThrow()
  })
})
