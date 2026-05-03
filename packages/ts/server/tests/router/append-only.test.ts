import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform, computeHash } from "@drakkar.software/starfish-protocol"
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
    name: "events",
    storagePath: "events",
    readRoles: ["admin"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    appendOnly: {},
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig) {
  const store = new MemoryObjectStore(new Map())
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
  }
  return { app: createSyncRouter(opts), store }
}

async function push(app: ReturnType<typeof createSyncRouter>, item: unknown, baseHash: string | null = null) {
  return app.request("/push/events", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: item, baseHash }),
  })
}

async function pull(app: ReturnType<typeof createSyncRouter>, checkpoint?: number) {
  const url = checkpoint != null ? `/pull/events?checkpoint=${checkpoint}` : "/pull/events"
  return app.request(url)
}

describe("appendOnly persist=true (stored array)", () => {
  it("first push creates array with one item, returns 200", async () => {
    const { app } = makeRouter(makeCol())
    const res = await push(app, { msg: "hello" })
    expect(res.status).toBe(200)
  })

  it("two sequential pushes → array has 2 items in order", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { msg: "first" })
    await push(app, { msg: "second" })
    const pullRes = await app.request("/pull/events")
    const body = await pullRes.json()
    expect(body.data.items).toEqual([{ msg: "first" }, { msg: "second" }])
  })

  it("baseHash from client is ignored (no 409)", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { msg: "first" })
    const res = await push(app, { msg: "second" }, "wrong-hash-doesnt-matter")
    expect(res.status).toBe(200)
  })

  it("GET /pull returns stored array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    await push(app, { n: 3 })
    const res = await app.request("/pull/events")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }])
  })

  it("custom appendField stores under that key", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { field: "logs" } }))
    await push(app, { msg: "entry" })
    const res = await app.request("/pull/events")
    const body = await res.json()
    expect(body.data.logs).toEqual([{ msg: "entry" }])
    expect(body.data.items).toBeUndefined()
  })

  it("signature verifier set globally → push without authorSignature succeeds", async () => {
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [makeCol()] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
      signatureVerifier: async () => false, // would reject non-appendOnly pushes
    }
    const app = createSyncRouter(opts)
    // appendOnly should bypass signature verification
    const res = await push(app, { msg: "unsigned" })
    expect(res.status).toBe(200)
  })
})

describe("appendOnly stored hash semantics (length-tagged)", () => {
  it("push response hash equals computeHash({ n, last })", async () => {
    const { app } = makeRouter(makeCol())
    const item = { msg: "hello" }
    const pushRes = await push(app, item)
    const body = await pushRes.json()
    const expected = await computeHash({ n: 1, last: item })
    expect(body.hash).toBe(expected)
  })

  it("duplicate item push produces different hash (length changes)", async () => {
    const { app } = makeRouter(makeCol())
    const item = { msg: "same" }
    const r1 = await (await push(app, item)).json()
    const r2 = await (await push(app, item)).json()
    expect(r1.hash).not.toBe(r2.hash)
  })
})

describe("appendOnly checkpoint pull", () => {
  it("?checkpoint=0 returns full array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    await push(app, { n: 3 })
    const res = await pull(app, 0)
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 1 }, { n: 2 }, { n: 3 }])
  })

  it("checkpoint after 2nd push returns only 3rd item", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const after2 = Date.now()
    await new Promise((r) => setTimeout(r, 2))
    await push(app, { n: 3 })
    const res = await pull(app, after2)
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 3 }])
  })

  it("checkpoint after all pushes returns empty array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const after = Date.now() + 1000
    const res = await pull(app, after)
    const body = await res.json()
    expect(body.data.items).toEqual([])
  })
})

describe("appendOnly persist=true with checkLastItem", () => {
  it("matching stored hash → accepted", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { checkLastItem: true } }))
    const item = { msg: "first" }
    await push(app, item, "")
    // Pull to get stored hash, use it as baseHash
    const pullBody = await (await pull(app)).json()
    const storedHash = pullBody.hash
    const res = await push(app, { msg: "second" }, storedHash)
    expect(res.status).toBe(200)
  })

  it("stale hash → 409", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { checkLastItem: true } }))
    await push(app, { msg: "first" }, "")
    const res = await push(app, { msg: "second" }, "stale-hash")
    expect(res.status).toBe(409)
  })

  it("empty store + empty baseHash → accepted", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { checkLastItem: true } }))
    const res = await push(app, { msg: "first" }, "")
    expect(res.status).toBe(200)
  })

  it("empty store + non-empty baseHash → 409", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { checkLastItem: true } }))
    const res = await push(app, { msg: "first" }, "wrong")
    expect(res.status).toBe(409)
  })

  it("concurrent appends with same baseHash → exactly one 200 and one 409", async () => {
    // Both pushes believe the store is empty (baseHash=""). Under the old pre-loop
    // checkLastItemConflict, the second push's retry would slip through because the
    // pre-loop check already passed. With the inlined check, every attempt re-reads
    // the stored hash, so the loser deterministically gets 409.
    const { app } = makeRouter(makeCol({ appendOnly: { checkLastItem: true } }))
    const [r1, r2] = await Promise.all([
      push(app, { n: 1 }, ""),
      push(app, { n: 2 }, ""),
    ])
    const statuses = [r1.status, r2.status].sort()
    expect(statuses).toEqual([200, 409])
  })
})

describe("appendOnly ?last=K pull", () => {
  it("?last=2 on 3-item array returns last 2 items", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    await push(app, { n: 3 })
    const res = await app.request("/pull/events?last=2")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 2 }, { n: 3 }])
  })

  it("?last=0 returns empty array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const res = await app.request("/pull/events?last=0")
    const body = await res.json()
    expect(body.data.items).toEqual([])
  })

  it("?last larger than array length returns full array", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const res = await app.request("/pull/events?last=100")
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 1 }, { n: 2 }])
  })

  it("?last combined with ?checkpoint: checkpoint filters first, then last K", async () => {
    const { app } = makeRouter(makeCol())
    await push(app, { n: 1 })
    await push(app, { n: 2 })
    const after2 = Date.now()
    await new Promise((r) => setTimeout(r, 2))
    await push(app, { n: 3 })
    await push(app, { n: 4 })
    await push(app, { n: 5 })
    // after2 filters to [3,4,5]; last=2 → [4,5]
    const res = await app.request(`/pull/events?checkpoint=${after2}&last=2`)
    const body = await res.json()
    expect(body.data.items).toEqual([{ n: 4 }, { n: 5 }])
  })

  it("?last without pushes returns empty array", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/pull/events?last=5")
    const body = await res.json()
    expect(body.data.items).toEqual([])
  })

  it("invalid ?last (non-integer) returns 400", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/pull/events?last=abc")
    expect(res.status).toBe(400)
  })

  it("negative ?last returns 400", async () => {
    const { app } = makeRouter(makeCol())
    const res = await app.request("/pull/events?last=-1")
    expect(res.status).toBe(400)
  })

  it("?last respects custom appendField", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { field: "logs" } }))
    await push(app, { msg: "a" })
    await push(app, { msg: "b" })
    await push(app, { msg: "c" })
    const res = await app.request("/pull/events?last=1")
    const body = await res.json()
    expect(body.data.logs).toEqual([{ msg: "c" }])
  })
})

describe("appendOnly config validation", () => {
  it("valid appendOnly (persist=true default) passes", () => {
    const errors = validateConfig({ version: 1, collections: [makeCol()] })
    expect(errors).toHaveLength(0)
  })

  it("appendOnly with clientEncrypted is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ clientEncrypted: true })],
    })
    expect(errors.some((e) => e.includes("clientEncrypted"))).toBe(true)
  })

  it("appendOnly with delegated encryption is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ encryption: "delegated" })],
    })
    expect(errors.some((e) => e.includes("delegated"))).toBe(true)
  })

  it("appendOnly with bundle is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [
        makeCol({ bundle: "myBundle", storagePath: "events/{identity}", encryption: "identity" }),
      ],
    })
    expect(errors.some((e) => e.includes("bundle"))).toBe(true)
  })
})
