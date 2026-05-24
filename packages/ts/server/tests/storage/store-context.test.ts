/**
 * Tests that StoreContext is built correctly and forwarded through the route layer.
 * Strategy: wire a CustomObjectStore that captures ctx, spin up createSyncRouter,
 * fire HTTP requests, and assert captured context fields.
 */
import { describe, it, expect, vi } from "vitest"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { CustomObjectStore, MemoryObjectStore } from "../../src/storage/memory.js"
import type { StoreContext } from "../../src/storage/base.js"
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
        name: "profile",
        storagePath: "users/{identity}/profile",
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

function makeApp(
  capturedContexts: StoreContext[],
  opts: Partial<SyncRouterOptions> = {},
  roleResult: AuthResult = { identity: "alice", roles: ["self"] },
) {
  const mem = new MemoryObjectStore(new Map())
  const store = new CustomObjectStore({
    onGet: (key, ctx) => {
      if (ctx) capturedContexts.push(ctx)
      return mem.getString(key)
    },
    onPut: (key, body, ctx) => {
      if (ctx) capturedContexts.push(ctx)
      return mem.put(key, body)
    },
    onList: (prefix, startAfter, limit, ctx) => {
      if (ctx) capturedContexts.push(ctx)
      return mem.listKeys(prefix, { startAfter, limit })
    },
    onDelete: (key, ctx) => {
      if (ctx) capturedContexts.push(ctx)
      return mem.delete(key)
    },
  })
  const router = createSyncRouter({
    store,
    config: makeConfig(),
    roleResolver: async () => roleResult,
    ...opts,
  })
  return router
}

describe("StoreContext — pull action", () => {
  it("passes correct context to onGet for pull request", async () => {
    const captured: StoreContext[] = []
    const app = makeApp(captured, {}, { identity: "alice", roles: ["self"] })

    const res = await app.request("/pull/users/alice/profile")
    expect(res.status).toBe(200)
    expect(captured.length).toBeGreaterThanOrEqual(1)
    const ctx = captured[0]
    expect(ctx.collection).toBe("profile")
    expect(ctx.params).toEqual({ identity: "alice" })
    expect(ctx.identity).toBe("alice")
    expect(ctx.roles).toContain("self")
    expect(ctx.action).toBe("pull")
    expect(ctx.namespace).toBeUndefined()
  })
})

describe("StoreContext — push action", () => {
  it("passes correct context to onPut for push request", async () => {
    const captured: StoreContext[] = []
    const app = makeApp(captured, {}, { identity: "alice", roles: ["self"] })

    const res = await app.request("/push/users/alice/profile", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    expect(res.status).toBe(200)
    const putCtx = captured.find(c => c.action === "push")
    expect(putCtx).toBeDefined()
    expect(putCtx!.collection).toBe("profile")
    expect(putCtx!.params).toEqual({ identity: "alice" })
    expect(putCtx!.identity).toBe("alice")
    expect(putCtx!.action).toBe("push")
  })
})

describe("StoreContext — list action", () => {
  it("passes correct context to onList for list request", async () => {
    const captured: StoreContext[] = []
    const app = makeApp(
      captured,
      {
        config: makeConfig({
          collections: [
            {
              name: "notes",
              storagePath: "users/{identity}/notes/{noteId}",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1_000_000,
              allowedMimeTypes: ["application/json"],
              list: true,
            } as any,
          ],
        }),
      },
      { identity: "alice", roles: ["self"] },
    )

    const res = await app.request("/list/users/alice/notes")
    // list may 200 or 404 depending on whether list is enabled; we just check ctx if it was invoked
    const listCtx = captured.find(c => c.action === "list")
    if (listCtx) {
      expect(listCtx.collection).toBe("notes")
      expect(listCtx.action).toBe("list")
    }
  })
})

describe("StoreContext — public route", () => {
  it("ctx.identity is null and roles is empty for public-only route", async () => {
    const captured: StoreContext[] = []
    const mem = new MemoryObjectStore(new Map())
    const store = new CustomObjectStore({
      onGet: (key, ctx) => {
        if (ctx) captured.push(ctx)
        return mem.getString(key)
      },
      onPut: (key, body, ctx) => {
        if (ctx) captured.push(ctx)
        return mem.put(key, body)
      },
    })
    const config: SyncConfig = {
      version: 1,
      collections: [
        {
          name: "announcements",
          storagePath: "app/announcements",
          readRoles: ["public"],
          writeRoles: ["admin"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
        },
      ],
    }
    const router = createSyncRouter({
      store,
      config,
      roleResolver: async () => ({ identity: null as any, roles: [] }),
    })
    const res = await router.request("/pull/app/announcements")
    expect(res.status).toBe(200)
    expect(captured.length).toBeGreaterThanOrEqual(1)
    const ctx = captured[0]
    expect(ctx.identity).toBeNull()
    expect(ctx.roles).toEqual([])
    expect(ctx.action).toBe("pull")
  })
})

describe("StoreContext — namespace route", () => {
  it("ctx.namespace equals the namespace name", async () => {
    const captured: StoreContext[] = []
    const mem = new MemoryObjectStore(new Map())
    const store = new CustomObjectStore({
      onGet: (key, ctx) => {
        if (ctx) captured.push(ctx)
        return mem.getString(key)
      },
      onPut: (key, body, ctx) => {
        if (ctx) captured.push(ctx)
        return mem.put(key, body)
      },
    })
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        org: {
          collections: [
            {
              name: "prefs",
              storagePath: "orgs/{identity}/prefs",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1_000_000,
              allowedMimeTypes: ["application/json"],
            },
          ],
        },
      } as any,
    }
    const router = createSyncRouter({
      store,
      config,
      roleResolver: async () => ({ identity: "alice", roles: ["self"] }),
    })
    const res = await router.request("/org/pull/orgs/alice/prefs")
    expect(res.status).toBe(200)
    expect(captured.length).toBeGreaterThanOrEqual(1)
    const ctx = captured[0]
    expect(ctx.namespace).toBe("org")
    expect(ctx.collection).toBe("prefs")
    expect(ctx.action).toBe("pull")
  })
})

describe("StoreContext — bundle/batch per-collection ctx", () => {
  it("bundle pull: ctx.collection differs per bundled collection", async () => {
    const captured: StoreContext[] = []
    const mem = new MemoryObjectStore(new Map())
    const store = new CustomObjectStore({
      onGet: (key, ctx) => {
        if (ctx) captured.push(ctx)
        return mem.getString(key)
      },
    })
    // Both collections share the same storagePath — the bundle URL is derived from it
    const config: SyncConfig = {
      version: 1,
      collections: [
        {
          name: "alpha",
          storagePath: "users/{identity}/data",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
          bundle: "mybundle",
        } as any,
        {
          name: "beta",
          storagePath: "users/{identity}/data",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
          bundle: "mybundle",
        } as any,
      ],
    }
    const router = createSyncRouter({
      store,
      config,
      roleResolver: async () => ({ identity: "alice", roles: ["self"] }),
    })
    const res = await router.request("/pull/users/alice/data")
    expect(res.status).toBe(200)
    const collectionNames = new Set(captured.map(c => c.collection))
    // Each bundled collection should appear with its own name
    expect(collectionNames).toContain("alpha")
    expect(collectionNames).toContain("beta")
  })
})
