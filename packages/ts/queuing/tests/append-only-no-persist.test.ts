import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  validateConfig,
  MemoryObjectStore,
  type SyncRouterOptions,
  type AuthResult,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"
import { MemoryQueue, createQueuingServerPlugin, type QueueConfig } from "../src/index.js"

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
    storagePath: "events/{eventId}",
    readRoles: ["public"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig, queueCollections: Record<string, QueueConfig> = {}) {
  const store = new MemoryObjectStore(new Map())
  const queue = new MemoryQueue()
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
    plugins: [createQueuingServerPlugin({ queue, collections: queueCollections })],
  }
  return { app: createSyncRouter(opts), store, queue }
}

async function push(app: ReturnType<typeof createSyncRouter>, path = "/push/events/evt-1", baseHash: string | null = null) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: { type: "click" }, baseHash }),
  })
}

describe("appendOnly+persist=false collection (replaces queueOnly)", () => {
  it("push returns hash and timestamp", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    const res = await push(app)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.hash).toBe("string")
    expect(body.hash).toHaveLength(64) // SHA-256 hex
    expect(typeof body.timestamp).toBe("number")
  })

  it("does not write to storage", async () => {
    const { app, store } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    await push(app)
    const stored = await store.getString("events/evt-1")
    expect(stored).toBeNull()
  })

  it("pull returns empty data (nothing stored)", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false }, readRoles: ["admin"] }))
    await push(app)
    const res = await app.request("/pull/events/evt-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({})
    expect(body.hash).toBe("")
  })

  it("accepts any baseHash (no conflict detection)", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    await push(app)
    const res = await push(app, "/push/events/evt-1", "arbitrary-hash-that-does-not-match")
    expect(res.status).toBe(200)
  })

  it("returns consistent hash for same data", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    const res1 = await push(app, "/push/events/evt-1")
    const res2 = await push(app, "/push/events/evt-2")
    const body1 = await res1.json()
    const body2 = await res2.json()
    expect(body1.hash).toBe(body2.hash)
  })

  it("publishes queue event when the queuing plugin is configured for the collection", async () => {
    const { app, queue } = makeRouter(
      makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }),
      { events: { topic: "events.created", includeParams: false } },
    )
    const res = await push(app)
    const pushBody = await res.json()

    expect(queue.messages).toHaveLength(1)
    const [subject, payload] = queue.messages[0]!
    const msg = JSON.parse(new TextDecoder().decode(payload))
    expect(subject).toBe("events.created")
    expect(msg.collection).toBe("events")
    expect(msg.hash).toBe(pushBody.hash)
    expect(msg.timestamp).toBe(pushBody.timestamp)
  })

  it("accepts push even without the collection configured for queuing", async () => {
    const { app, queue } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    const res = await push(app)
    expect(res.status).toBe(200)
    expect(queue.messages).toHaveLength(0)
  })

  it("still validates missing data field", async () => {
    const { app } = makeRouter(makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } }))
    const res = await app.request("/push/events/evt-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseHash: null }),
    })
    expect(res.status).toBe(400)
  })
})

describe("appendOnly+persist=false config validation", () => {
  it("valid appendOnly+persist=false JSON collection passes", () => {
    const errors = validateConfig({ version: 1, collections: [makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false } })] })
    expect(errors).toHaveLength(0)
  })

  it("appendOnly with binary collection is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false }, allowedMimeTypes: ["image/png"] })],
    })
    expect(errors.some((e) => e.includes("appendOnly cannot be used with binary collections"))).toBe(true)
  })

  it("appendOnly with pullOnly is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ appendOnly: { type: "by_timestamp", persist: false, requireAuthorSignature: false }, pullOnly: true })],
    })
    expect(errors.some((e) => e.includes("appendOnly cannot be used with pullOnly"))).toBe(true)
  })
})
