import { describe, it, expect } from "vitest"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
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

function makeRouter(config: SyncConfig, roleResolver?: SyncRouterOptions["roleResolver"]) {
  const store = new MemoryObjectStore(new Map())
  const app = createSyncRouter({
    store,
    config,
    roleResolver: roleResolver ?? (async () => ({ identity: "user-1", roles: ["self"] })),
  })
  return { app, store }
}

const settingsCollection = {
  name: "settings",
  storagePath: "users/{identity}/settings",
  readRoles: ["self"],
  writeRoles: ["self"],
  encryption: "none" as const,
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
}

const publicCollection = {
  name: "config",
  storagePath: "app/config",
  readRoles: ["public"],
  writeRoles: ["admin"],
  encryption: "none" as const,
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
}

describe("namespace routing", () => {
  it("namespaced pull works at /{ns}/pull/...", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [settingsCollection] },
      },
    })
    const res = await app.request("/tenantA/pull/users/user-1/settings")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({})
  })

  it("namespaced push works at /{ns}/push/...", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [settingsCollection] },
      },
    })
    const res = await app.request("/tenantA/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hash).toBeDefined()
    expect(body.timestamp).toBeDefined()
  })

  it("root collections are unaffected by namespaces", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [settingsCollection],
      namespaces: {
        tenantA: { collections: [{ ...settingsCollection, name: "prefs" }] },
      },
    })
    // Root still works
    const res = await app.request("/pull/users/user-1/settings")
    expect(res.status).toBe(200)
  })

  it("namespace and root routes are independent URL paths that both resolve correctly", async () => {
    const nsCollection = { ...settingsCollection, storagePath: "tenantA/users/{identity}/settings" }
    const { app } = makeRouter({
      version: 1,
      collections: [settingsCollection],
      namespaces: {
        tenantA: { collections: [nsCollection] },
      },
    })

    // Push to namespace
    const nsPush = await app.request("/tenantA/push/tenantA/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { source: "tenantA" }, baseHash: null }),
    })
    expect(nsPush.status).toBe(200)

    // Push to root
    const rootPush = await app.request("/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { source: "root" }, baseHash: null }),
    })
    expect(rootPush.status).toBe(200)

    // Namespace and root read their own data
    const nsBody = await (await app.request("/tenantA/pull/tenantA/users/user-1/settings")).json()
    const rootBody = await (await app.request("/pull/users/user-1/settings")).json()

    expect(nsBody.data?.source).toBe("tenantA")
    expect(rootBody.data?.source).toBe("root")
  })

  it("multiple namespaces with distinct storagePaths are isolated from each other", async () => {
    const colA = { ...settingsCollection, storagePath: "tenantA/users/{identity}/settings" }
    const colB = { ...settingsCollection, storagePath: "tenantB/users/{identity}/settings" }

    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [colA] },
        tenantB: { collections: [colB] },
      },
    })

    // Push to tenantA
    await app.request("/tenantA/push/tenantA/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { tenant: "A" }, baseHash: null }),
    })

    // tenantB has a different storagePath — unaffected
    const bRes = await app.request("/tenantB/pull/tenantB/users/user-1/settings")
    const bBody = await bRes.json()
    expect(bBody.data).toEqual({})
  })

  it("namespaced route returns 404 for unknown namespace", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [settingsCollection] },
      },
    })
    const res = await app.request("/tenantB/pull/users/user-1/settings")
    expect(res.status).toBe(404)
  })

  it("auth is enforced on namespaced routes", async () => {
    const { app } = makeRouter(
      {
        version: 1,
        collections: [],
        namespaces: {
          tenantA: { collections: [settingsCollection] },
        },
      },
      async () => ({ identity: "user-2", roles: [] }),
    )
    // user-2 accessing user-1's data should be forbidden (no self role)
    const res = await app.request("/tenantA/pull/users/user-1/settings")
    expect(res.status).toBe(403)
  })

  it("health endpoint remains at root /health, not namespaced", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [settingsCollection] },
      },
    })
    const res = await app.request("/health")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.ok).toBe(true)
  })
})

describe("namespace middleware propagation", () => {
  it("CORS headers are present on namespaced routes when cors is enabled", async () => {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [],
        namespaces: { tenantA: { collections: [settingsCollection] } },
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      cors: { origin: "https://example.com" },
    })
    const res = await app.request("/tenantA/pull/users/user-1/settings", {
      headers: { Origin: "https://example.com" },
    })
    expect(res.status).toBe(200)
    expect(res.headers.get("access-control-allow-origin")).toBe("https://example.com")
  })

  it("CORS preflight OPTIONS works on namespaced routes", async () => {
    const store = new MemoryObjectStore(new Map())
    const app = createSyncRouter({
      store,
      config: {
        version: 1,
        collections: [],
        namespaces: { tenantA: { collections: [settingsCollection] } },
      },
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      cors: { origin: "https://example.com" },
    })
    const res = await app.request("/tenantA/push/users/user-1/settings", {
      method: "OPTIONS",
      headers: { Origin: "https://example.com" },
    })
    expect(res.status).toBe(204)
    expect(res.headers.get("access-control-allow-origin")).toBe("https://example.com")
  })
})

describe("namespace push auth", () => {
  it("auth is enforced on namespaced push", async () => {
    const { app } = makeRouter(
      {
        version: 1,
        collections: [],
        namespaces: {
          tenantA: { collections: [settingsCollection] },
        },
      },
      async () => ({ identity: "user-2", roles: [] }),
    )
    // user-2 has no write role to user-1's settings
    const res = await app.request("/tenantA/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(403)
  })

  it("namespaced push data is readable via namespaced pull", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: { tenantA: { collections: [settingsCollection] } },
    })
    await app.request("/tenantA/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { color: "blue" }, baseHash: null }),
    })
    const res = await app.request("/tenantA/pull/users/user-1/settings")
    const body = await res.json()
    expect(body.data.color).toBe("blue")
  })
})

describe("namespace shared storagePath behavior", () => {
  it("two namespaces with the same storagePath share underlying data (documented behavior)", async () => {
    // Namespaces are URL prefixes only; storage isolation requires distinct storagePaths
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [settingsCollection] },
        tenantB: { collections: [settingsCollection] },
      },
    })

    // Push via tenantA
    await app.request("/tenantA/push/users/user-1/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { source: "A" }, baseHash: null }),
    })

    // tenantB resolves the same storage key and sees tenantA's data
    const res = await app.request("/tenantB/pull/users/user-1/settings")
    const body = await res.json()
    expect(body.data.source).toBe("A")
  })
})

describe("bundled collections inside namespace", () => {
  const bundleConfig: SyncConfig = {
    version: 1,
    collections: [],
    namespaces: {
      tenantA: {
        collections: [
          {
            name: "prefs",
            storagePath: "tenantA/users/{identity}/data",
            bundle: "userdata",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "identity",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
          {
            name: "profile",
            storagePath: "tenantA/users/{identity}/data",
            bundle: "userdata",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "identity",
            maxBodyBytes: 1_000_000,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
    },
  }

  function makeBundleRouter() {
    const store = new MemoryObjectStore(new Map())
    return createSyncRouter({
      store,
      config: bundleConfig,
      roleResolver: async () => ({ identity: "user-1", roles: ["self"] }),
      encryptionSecret: "test-secret",
    })
  }

  it("bundle pull returns all collections in the bundle", async () => {
    const app = makeBundleRouter()
    const res = await app.request("/tenantA/pull/tenantA/users/user-1/data")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toBeDefined()
    expect(body.collections.prefs).toBeDefined()
    expect(body.collections.profile).toBeDefined()
  })

  it("bundle push updates a single collection in the namespace bundle", async () => {
    const app = makeBundleRouter()
    const res = await app.request("/tenantA/push/tenantA/users/user-1/data/prefs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hash).toBeDefined()
  })

  it("bundle push is reflected in bundle pull", async () => {
    const app = makeBundleRouter()
    // Push prefs
    await app.request("/tenantA/push/tenantA/users/user-1/data/prefs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })
    // Pull bundle — prefs should have data, profile should be empty
    const res = await app.request("/tenantA/pull/tenantA/users/user-1/data")
    const body = await res.json()
    expect(body.collections.prefs.data).toEqual({ theme: "dark" })
    expect(body.collections.profile.data).toEqual({})
  })
})

describe("namespace batch pull", () => {
  it("/{ns}/batch/pull returns collections within that namespace", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [publicCollection] },
      },
    })
    const res = await app.request("/tenantA/batch/pull?collections=config")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.config).toBeDefined()
    expect(body.collections.config.error).toBeUndefined()
  })

  it("/{ns}/batch/pull does not find root collections", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [publicCollection],
      namespaces: {
        tenantA: { collections: [] },
      },
    })
    const res = await app.request("/tenantA/batch/pull?collections=config")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.config.error).toBe("Collection not found")
  })

  it("/batch/pull does not find namespaced collections", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [publicCollection] },
      },
    })
    const res = await app.request("/batch/pull?collections=config")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.config.error).toBe("Collection not found")
  })

  it("/{ns}/batch/pull returns 400 for missing collections param", async () => {
    const { app } = makeRouter({
      version: 1,
      collections: [],
      namespaces: {
        tenantA: { collections: [publicCollection] },
      },
    })
    const res = await app.request("/tenantA/batch/pull")
    expect(res.status).toBe(400)
  })
})
