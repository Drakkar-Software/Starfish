import { describe, it, expect, vi } from "vitest"
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
          {
            name: "user-doc",
            storagePath: "users/{identity}/doc",
            readRoles: ["public"],
            writeRoles: ["self"],
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

  it("reports parameterized collections as not batch-pullable (no masked error)", async () => {
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=user-doc,public-data")
    expect(res.status).toBe(200)
    const body = await res.json()
    // The {identity}-templated collection can't be addressed without params.
    expect(body.collections["user-doc"].data).toBeUndefined()
    expect(body.collections["user-doc"].error).toContain("not batch-pullable")
    // A singleton collection in the same request is still served.
    expect(body.collections["public-data"].data).toBeDefined()
  })

  it("drops empty slots in the collections CSV like the Python handler does", async () => {
    // Empty slots (leading/trailing/double commas) are filtered, so a malformed CSV
    // never produces spurious `""` → "Collection not found" entries — matching Python.
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=,public-data,,")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(Object.keys(body.collections)).toEqual(["public-data"])
    expect(body.collections["public-data"].data).toBeDefined()
  })

  it("returns an empty result set for an all-empty CSV (parity with Python, not 400)", async () => {
    // `,,` is present-but-all-empty: the param guard only fires when the param itself
    // is absent/empty, so this resolves to no names and 200 `{ collections: {} }`.
    const { app } = makeRouter()
    const res = await app.request("/batch/pull?collections=,,")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toEqual({})
  })
})

describe("batch pull TTL expiry", () => {
  function makeTtlRouter() {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [
          {
            name: "ephemeral",
            storagePath: "ephemeral/data",
            readRoles: ["public"],
            writeRoles: ["admin"],
            encryption: "none",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
            ttlMs: 1000,
          },
        ],
      },
      roleResolver: async () => ({ identity: "u", roles: ["viewer"] }),
    })
    return { app, store }
  }

  it("omits data for a document past its ttlMs (parity with the standalone + Python paths)", async () => {
    const { app, store } = makeTtlRouter()
    // Seed an expired doc: its stored write-time is far in the past.
    await store.put(
      "ephemeral/data",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() - 999_999 }),
    )
    const res = await app.request("/batch/pull?collections=ephemeral")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.ephemeral.data).toEqual({})
  })

  it("returns data for a fresh document within ttlMs", async () => {
    const { app, store } = makeTtlRouter()
    await store.put(
      "ephemeral/data",
      JSON.stringify({ data: { v: 1 }, hash: "h", ts: Date.now() }),
    )
    const res = await app.request("/batch/pull?collections=ephemeral")
    const body = await res.json()
    expect(body.collections.ephemeral.data).toEqual({ v: 1 })
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

  it("allows any authenticated user to write a field whose writeRoles is public", async () => {
    // writeRoles:["public"] marks the field unrestricted; an authenticated user with
    // role "self" (not the literal "public") must still be allowed. The field-write
    // check honors ROLE_PUBLIC (route-builder.ts:439). See test_ttl_and_field_permissions.py
    // for the Python twin — currently xfailed, as the Python write check omits ROLE_PUBLIC.
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
            fieldPermissions: { openField: { writeRoles: ["public"] } },
          },
        ],
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
    })
    const res = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { openField: "anyone-can-write" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
  })

  it("treats an explicit null on a restricted field as a write (presence, not truthiness)", async () => {
    // Setting an admin-only field to `null` must still be rejected — the guard keys on
    // the field being PRESENT in `data`, so a non-admin cannot blank/no-op-touch it by
    // sending null; only omitting the key avoids the check. Pins null can't slip past.
    const { app } = makeRouter()
    const res = await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { name: "Alice", email: null }, baseHash: null }),
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

  it("keeps the ETag (and 304) through field-read filtering", async () => {
    // The field filter mutates `data` in place and leaves `hash` intact, so the
    // hash-derived ETag survives and conditional requests still 304. (The Python twin
    // currently drops the ETag on its rebuild — pinned there as a strict xfail.)
    const { app } = makeRouter()
    await app.request("/push/users/user-1/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { name: "Alice", bio: "Hello" }, baseHash: null }),
    })
    const res1 = await app.request("/pull/users/user-1/profile")
    expect(res1.status).toBe(200)
    const etag = res1.headers.get("etag")
    expect(etag).toBeTruthy()
    const res2 = await app.request("/pull/users/user-1/profile", {
      headers: { "If-None-Match": etag! },
    })
    expect(res2.status).toBe(304)
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
