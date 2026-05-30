import { describe, it, expect, beforeEach } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"
import { validateConfig } from "../../src/config/validate.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeCol(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "chat",
    storagePath: "chats/{groupId}/{day}",
    readRoles: ["member"],
    writeRoles: ["member"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    listable: true,
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig, identity = "user-1", roles = ["member"]) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity, roles }),
  }
  return { app: createSyncRouter(opts), store }
}

async function pushDoc(
  app: ReturnType<typeof createSyncRouter>,
  path: string,
  data: Record<string, unknown> = { msg: "hello" },
) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data, baseHash: null }),
  })
}

// ── Happy-path tests ──────────────────────────────────────────────────────────

describe("list endpoint — basic", () => {
  it("returns empty items when no documents exist", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items).toEqual([])
    expect(body.hasMore).toBe(false)
  })

  it("lists a single document", async () => {
    const { app } = makeRouter(makeCol())
    await pushDoc(app, "/push/chats/group-1/2026-04-13")
    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items).toContain("2026-04-13")
    expect(body.hasMore).toBe(false)
  })

  it("lists multiple documents in sorted order", async () => {
    const { app } = makeRouter(makeCol())
    await pushDoc(app, "/push/chats/group-1/2026-04-13")
    await pushDoc(app, "/push/chats/group-1/2026-04-12")
    await pushDoc(app, "/push/chats/group-1/2026-04-11")
    const res = await app.request("/list/chats/group-1")
    const body = await res.json()
    expect(body.items).toEqual(["2026-04-11", "2026-04-12", "2026-04-13"])
    expect(body.hasMore).toBe(false)
  })

  it("does not mix documents from different groups", async () => {
    const { app } = makeRouter(makeCol())
    await pushDoc(app, "/push/chats/group-1/2026-04-13")
    await pushDoc(app, "/push/chats/group-2/2026-04-13")
    const res = await app.request("/list/chats/group-1")
    const body = await res.json()
    expect(body.items).toEqual(["2026-04-13"])
  })
})

// ── Pagination tests ──────────────────────────────────────────────────────────

describe("list endpoint — pagination", () => {
  async function seedDays(app: ReturnType<typeof createSyncRouter>, count: number) {
    for (let i = 1; i <= count; i++) {
      await pushDoc(app, `/push/chats/group-1/day-${String(i).padStart(3, "0")}`)
    }
  }

  it("respects ?limit parameter", async () => {
    const { app } = makeRouter(makeCol())
    await seedDays(app, 5)
    const res = await app.request("/list/chats/group-1?limit=3")
    const body = await res.json()
    expect(body.items).toHaveLength(3)
    expect(body.hasMore).toBe(true)
  })

  it("?after enables cursor pagination", async () => {
    const { app } = makeRouter(makeCol())
    await seedDays(app, 5)

    const page1 = await (await app.request("/list/chats/group-1?limit=3")).json()
    expect(page1.items).toHaveLength(3)
    expect(page1.hasMore).toBe(true)

    const lastItem = page1.items[2]
    const page2 = await (await app.request(`/list/chats/group-1?limit=3&after=${lastItem}`)).json()
    expect(page2.items).toHaveLength(2)
    expect(page2.hasMore).toBe(false)

    // Pages should be disjoint
    const allItems = [...page1.items, ...page2.items]
    expect(new Set(allItems).size).toBe(5)
  })

  it("caps limit at LIST_MAX_LIMIT (1000)", async () => {
    const { app } = makeRouter(makeCol())
    await seedDays(app, 3)
    // Asking for more than 1000 still works — just returns all 3
    const res = await app.request("/list/chats/group-1?limit=9999")
    const body = await res.json()
    expect(body.items).toHaveLength(3)
    expect(body.hasMore).toBe(false)
  })

  it("returns 400 for invalid limit", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/list/chats/group-1?limit=abc")
    expect(res.status).toBe(400)
  })
})

// ── Auth tests ────────────────────────────────────────────────────────────────

describe("list endpoint — auth", () => {
  it("returns 403 when caller lacks readRoles", async () => {
    const { app } = makeRouter(makeCol(), "user-1", ["viewer"])
    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(403)
  })

  it("allows public access when readRoles includes 'public'", async () => {
    const col = makeCol({ readRoles: ["public"], writeRoles: ["public"] })
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [col] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "", roles: [] }),
    }
    const app = createSyncRouter(opts)
    await pushDoc(app, "/push/chats/group-1/2026-04-13")
    const res = await app.request("/list/chats/group-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items).toContain("2026-04-13")
  })

  it("list route works when self role requires identity param in a deeper path", async () => {
    // data/{identity}/{bucket} — list route is /list/data/:identity
    // self role is granted because {identity} IS in the list route path
    const col: CollectionConfig = {
      name: "buckets",
      storagePath: "data/{identity}/{bucket}",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [col] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "alice", roles: [] }),
    }
    const app = createSyncRouter(opts)
    // Push as alice
    await app.request("/push/data/alice/notes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })
    // List as alice — self role granted
    const res = await app.request("/list/data/alice")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items).toContain("notes")
  })
})

// ── Single-param storagePath ──────────────────────────────────────────────────

describe("list endpoint — single path param", () => {
  it("lists under a single-param storagePath", async () => {
    const col: CollectionConfig = {
      name: "notes",
      storagePath: "notes/{userId}",
      readRoles: ["admin"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const { app } = makeRouter(col, "admin", ["admin"])
    await pushDoc(app, "/push/notes/alice")
    await pushDoc(app, "/push/notes/bob")
    const res = await app.request("/list/notes")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items.sort()).toEqual(["alice", "bob"])
  })
})

// ── Namespace support ─────────────────────────────────────────────────────────

describe("list endpoint — namespaces", () => {
  it("list route is accessible under a namespace prefix", async () => {
    const col = makeCol()
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: { v2: { collections: [col] } },
    }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["member"] }),
    }
    const app = createSyncRouter(opts)
    await app.request("/v2/push/chats/group-1/2026-04-13", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { msg: "hi" }, baseHash: null }),
    })
    const res = await app.request("/v2/list/chats/group-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.items).toContain("2026-04-13")
  })
})

// ── Config validation ─────────────────────────────────────────────────────────

describe("listable config validation", () => {
  it("valid listable collection passes validation", () => {
    const errors = validateConfig({ version: 1, collections: [makeCol()] })
    expect(errors).toHaveLength(0)
  })

  it("listable without path params is rejected", () => {
    const col: CollectionConfig = {
      name: "settings",
      storagePath: "settings",
      readRoles: ["admin"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const errors = validateConfig({ version: 1, collections: [col] })
    expect(errors.some((e) => e.includes("at least one path parameter"))).toBe(true)
  })

  it("listable with static last segment is rejected", () => {
    const col: CollectionConfig = {
      name: "log",
      storagePath: "users/{userId}/log",
      readRoles: ["admin"],
      writeRoles: ["admin"],
      encryption: "none",
      maxBodyBytes: 65536,
      allowedMimeTypes: ["application/json"],
      listable: true,
    }
    const errors = validateConfig({ version: 1, collections: [col] })
    expect(errors.some((e) => e.includes("last storagePath segment"))).toBe(true)
  })

  it("listable with appendOnly+persist=false is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ appendOnly: { type: "by_timestamp", persist: false } })],
    })
    expect(errors.some((e) => e.includes("listable cannot be used with appendOnly+persist=false"))).toBe(true)
  })

  it("listable with bundle is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [
        makeCol({ bundle: "my-bundle", encryption: "none", storagePath: "data/{identity}/{day}" }),
      ],
    })
    expect(errors.some((e) => e.includes("listable cannot be used with bundle"))).toBe(true)
  })
})

// ── include=values (listValues) tests ─────────────────────────────────────────

describe("list endpoint — include=values", () => {
  const valuesCol = (overrides: Partial<CollectionConfig> = {}) =>
    makeCol({ listValues: true, ...overrides })

  it("returns each document's data and hash alongside its key", async () => {
    const { app } = makeRouter(valuesCol())
    await pushDoc(app, "/push/chats/group-1/2026-04-12", { msg: "older" })
    await pushDoc(app, "/push/chats/group-1/2026-04-13", { msg: "newer" })

    const res = await app.request("/list/chats/group-1?include=values")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.hasMore).toBe(false)
    expect(body.items.map((i: { key: string }) => i.key)).toEqual(["2026-04-12", "2026-04-13"])
    expect(body.items[0].data).toEqual({ msg: "older" })
    expect(body.items[1].data).toEqual({ msg: "newer" })
    // hash is the stored document hash (sha256 hex)
    expect(body.items[0].hash).toHaveLength(64)
  })

  it("honors ?limit and ?after with values", async () => {
    const { app } = makeRouter(valuesCol())
    for (let i = 1; i <= 5; i++) {
      await pushDoc(app, `/push/chats/group-1/day-${String(i).padStart(2, "0")}`, { n: i })
    }
    const page1 = await (await app.request("/list/chats/group-1?include=values&limit=2")).json()
    expect(page1.items.map((i: { key: string }) => i.key)).toEqual(["day-01", "day-02"])
    expect(page1.hasMore).toBe(true)

    const after = page1.items.at(-1).key
    const page2 = await (
      await app.request(`/list/chats/group-1?include=values&limit=2&after=${after}`)
    ).json()
    expect(page2.items.map((i: { key: string }) => i.key)).toEqual(["day-03", "day-04"])
    expect(page2.items[0].data).toEqual({ n: 3 })
  })

  it("rejects include=values when the collection has not opted in", async () => {
    const { app } = makeRouter(makeCol()) // listable but not listValues
    await pushDoc(app, "/push/chats/group-1/2026-04-13")
    const res = await app.request("/list/chats/group-1?include=values")
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toContain("include=values is not enabled")
  })

  it("falls back to keys-only when include is absent or not 'values'", async () => {
    const { app } = makeRouter(valuesCol())
    await pushDoc(app, "/push/chats/group-1/2026-04-13", { msg: "hi" })
    const res = await app.request("/list/chats/group-1?include=keys")
    const body = await res.json()
    expect(body.items).toEqual(["2026-04-13"])
  })

  it("applies fieldPermissions read-stripping to returned values", async () => {
    // Caller has role "member" only; the `secret` field requires "admin".
    const { app } = makeRouter(
      valuesCol({ fieldPermissions: { secret: { readRoles: ["admin"] } } }),
    )
    await pushDoc(app, "/push/chats/group-1/2026-04-13", { msg: "hi", secret: "x" })
    const res = await app.request("/list/chats/group-1?include=values")
    const body = await res.json()
    expect(body.items[0].data).toEqual({ msg: "hi" })
    expect(body.items[0].data.secret).toBeUndefined()
  })

  it("enforces read auth before returning values (403 for the wrong role)", async () => {
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [valuesCol()] }
    // Seed a doc as a member, then query as a non-member.
    const writer = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "u1", roles: ["member"] }),
    })
    await pushDoc(writer, "/push/chats/group-1/2026-04-13")
    const reader = createSyncRouter({
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "u2", roles: ["stranger"] }),
    })
    const res = await reader.request("/list/chats/group-1?include=values")
    expect(res.status).toBe(403)
  })

  it("validateConfig rejects listValues without listable", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ listable: false, listValues: true })],
    })
    expect(errors.some((e) => e.includes("listValues requires listable"))).toBe(true)
  })
})
