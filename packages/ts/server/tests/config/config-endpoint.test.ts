import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  type SyncRouterOptions,
  type AuthResult,
} from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "posts",
    storagePath: "posts/{postId}",
    readRoles: ["public"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function makeRouter(
  cols: CollectionConfig[],
  overrides: Partial<SyncRouterOptions> = {},
  namespaces?: SyncConfig["namespaces"],
) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: cols, namespaces }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
    ...overrides,
  }
  return createSyncRouter(opts)
}

describe("GET /config — disabled by default", () => {
  it("returns 404 when configEndpoint is not set", async () => {
    const app = makeRouter([makeCol()])
    const res = await app.request("/config")
    expect(res.status).toBe(404)
  })
})

describe("GET /config — auth: public", () => {
  it("returns all collections without calling roleResolver", async () => {
    const app = makeRouter(
      [makeCol(), makeCol({ name: "comments", storagePath: "comments/{id}", writeRoles: ["user"] })],
      { configEndpoint: { auth: "public" } },
    )
    const res = await app.request("/config")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toHaveLength(2)
    expect(body.collections[0].name).toBe("posts")
    expect(body.collections[1].name).toBe("comments")
  })

  it("includes publicKey when set on collection", async () => {
    const app = makeRouter(
      [makeCol({ publicKey: "base64encodedkey==" })],
      { configEndpoint: { auth: "public" } },
    )
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.collections[0].publicKey).toBe("base64encodedkey==")
  })

  it("omits publicKey when not set", async () => {
    const app = makeRouter([makeCol()], { configEndpoint: { auth: "public" } })
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.collections[0].publicKey).toBeUndefined()
  })

  it("includes correct capability flags", async () => {
    const app = makeRouter(
      [makeCol({ pullOnly: true, queueOnly: undefined, ttlMs: 3600000 })],
      { configEndpoint: { auth: "public" } },
    )
    const res = await app.request("/config")
    const body = await res.json()
    const col = body.collections[0]
    expect(col.maxBodyBytes).toBe(65536)
    expect(col.encryption).toBe("none")
    expect(col.allowedMimeTypes).toEqual(["application/json"])
    expect(col.pullOnly).toBe(true)
    expect(col.ttlMs).toBe(3600000)
  })

  it("includes namespace collections", async () => {
    const nsCol = makeCol({ name: "settings", storagePath: "settings/{id}" })
    const app = makeRouter(
      [makeCol()],
      { configEndpoint: { auth: "public" } },
      { tenantA: { collections: [nsCol] } },
    )
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.collections).toHaveLength(1)
    expect(body.namespaces?.tenantA?.collections).toHaveLength(1)
    expect(body.namespaces?.tenantA?.collections[0].name).toBe("settings")
  })
})

describe("GET /config — auth: role-filtered", () => {
  it("returns collections visible to caller's roles", async () => {
    const app = makeRouter(
      [
        makeCol({ name: "posts", readRoles: ["public"], writeRoles: ["admin"] }),
        makeCol({ name: "secrets", storagePath: "secrets/{id}", readRoles: ["admin"], writeRoles: ["admin"] }),
      ],
      {
        configEndpoint: { auth: "role-filtered" },
        roleResolver: async () => ({ identity: "anon", roles: ["public"] }),
      },
    )
    const res = await app.request("/config")
    const body = await res.json()
    // "public" role matches readRoles of "posts" but not "secrets"
    expect(body.collections).toHaveLength(1)
    expect(body.collections[0].name).toBe("posts")
  })

  it("shows nothing when caller has no matching roles", async () => {
    const app = makeRouter(
      [makeCol({ readRoles: ["admin"], writeRoles: ["admin"] })],
      {
        configEndpoint: { auth: "role-filtered" },
        roleResolver: async () => ({ identity: "user", roles: ["user"] }),
      },
    )
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.collections).toHaveLength(0)
  })

  it("shows collection when caller matches writeRoles only", async () => {
    const app = makeRouter(
      [makeCol({ name: "pushonly", storagePath: "p/{id}", readRoles: [], writeRoles: ["writer"], pullOnly: false, pushOnly: true })],
      {
        configEndpoint: { auth: "role-filtered" },
        roleResolver: async () => ({ identity: "w", roles: ["writer"] }),
      },
    )
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.collections).toHaveLength(1)
  })

  it("filters namespace collections by roles", async () => {
    const nsPublic = makeCol({ name: "public", storagePath: "pub/{id}", readRoles: ["public"], writeRoles: ["admin"] })
    const nsSecret = makeCol({ name: "secret", storagePath: "sec/{id}", readRoles: ["admin"], writeRoles: ["admin"] })
    const app = makeRouter(
      [],
      {
        configEndpoint: { auth: "role-filtered" },
        roleResolver: async () => ({ identity: "anon", roles: ["public"] }),
      },
      { ns1: { collections: [nsPublic, nsSecret] } },
    )
    const res = await app.request("/config")
    const body = await res.json()
    expect(body.namespaces?.ns1?.collections).toHaveLength(1)
    expect(body.namespaces?.ns1?.collections[0].name).toBe("public")
  })

  it("returns empty collections when roleResolver throws", async () => {
    const app = makeRouter(
      [makeCol()],
      {
        configEndpoint: { auth: "role-filtered" },
        roleResolver: async () => { throw new Error("auth failure") },
      },
    )
    const res = await app.request("/config")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections).toHaveLength(0)
  })
})
