import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { MemoryQueue } from "../../src/queue/memory.js"
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
    storagePath: "events/{eventId}",
    readRoles: ["public"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function makeRouter(col: CollectionConfig, queue?: MemoryQueue) {
  const store = new MemoryObjectStore(new Map())
  const q = queue ?? new MemoryQueue()
  const config: SyncConfig = { version: 1, collections: [col] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
    queue: q,
  }
  return { app: createSyncRouter(opts), store, queue: q }
}

async function push(app: ReturnType<typeof createSyncRouter>, path = "/push/events/evt-1", baseHash: string | null = null) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: { type: "click" }, baseHash }),
  })
}

describe("queueOnly collection", () => {
  it("push returns hash and timestamp", async () => {
    const { app } = makeRouter(makeCol({ queueOnly: true }))
    const res = await push(app)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(typeof body.hash).toBe("string")
    expect(body.hash).toHaveLength(64) // SHA-256 hex
    expect(typeof body.timestamp).toBe("number")
  })

  it("does not write to storage", async () => {
    const { app, store } = makeRouter(makeCol({ queueOnly: true }))
    await push(app)
    const stored = await store.getString("events/evt-1")
    expect(stored).toBeNull()
  })

  it("pull returns empty data (nothing stored)", async () => {
    const { app } = makeRouter(makeCol({ queueOnly: true, readRoles: ["admin"] }))
    await push(app)
    const res = await app.request("/pull/events/evt-1")
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.data).toEqual({})
    expect(body.hash).toBe("")
  })

  it("accepts any baseHash (no conflict detection)", async () => {
    const { app } = makeRouter(makeCol({ queueOnly: true }))
    // First push
    await push(app)
    // Second push with arbitrary baseHash should also succeed
    const res = await push(app, "/push/events/evt-1", "arbitrary-hash-that-does-not-match")
    expect(res.status).toBe(200)
  })

  it("returns consistent hash for same data", async () => {
    const { app } = makeRouter(makeCol({ queueOnly: true }))
    const res1 = await push(app, "/push/events/evt-1")
    const res2 = await push(app, "/push/events/evt-2")
    const body1 = await res1.json()
    const body2 = await res2.json()
    // Same data → same hash
    expect(body1.hash).toBe(body2.hash)
  })

  it("publishes queue event when queue configured", async () => {
    const q = new MemoryQueue()
    const { app } = makeRouter(
      makeCol({ queueOnly: true, queue: { topic: "events.created", includeParams: false } }),
      q,
    )
    const res = await push(app)
    const pushBody = await res.json()

    expect(q.messages).toHaveLength(1)
    const [subject, payload] = q.messages[0]!
    const msg = JSON.parse(new TextDecoder().decode(payload))
    expect(subject).toBe("events.created")
    expect(msg.collection).toBe("events")
    expect(msg.hash).toBe(pushBody.hash)
    expect(msg.timestamp).toBe(pushBody.timestamp)
  })

  it("accepts push even without queue configured", async () => {
    // queueOnly without queue: collection is ephemeral (no storage, no queue)
    const col = makeCol({ queueOnly: true, queue: undefined })
    const { app } = makeRouter(col)
    const res = await push(app)
    expect(res.status).toBe(200)
  })

  it("still validates missing data field", async () => {
    const { app } = makeRouter(makeCol({ queueOnly: true }))
    const res = await app.request("/push/events/evt-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ baseHash: null }), // no data field
    })
    expect(res.status).toBe(400)
  })
})

describe("queueOnly config validation", () => {
  it("valid queueOnly JSON collection passes", () => {
    const errors = validateConfig({ version: 1, collections: [makeCol({ queueOnly: true })] })
    expect(errors).toHaveLength(0)
  })

  it("queueOnly with binary collection is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ queueOnly: true, allowedMimeTypes: ["image/png"] })],
    })
    expect(errors.some((e) => e.includes("queueOnly cannot be used with binary collections"))).toBe(true)
  })

  it("queueOnly with pullOnly is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [makeCol({ queueOnly: true, pullOnly: true })],
    })
    expect(errors.some((e) => e.includes("queueOnly cannot be used with pullOnly"))).toBe(true)
  })

  it("queueOnly with remote is rejected", () => {
    const errors = validateConfig({
      version: 1,
      collections: [
        makeCol({
          queueOnly: true,
          remote: {
            url: "https://primary.example.com",
            pullPath: "/pull/events/{eventId}",
            intervalMs: 60000,
            headers: {},
            writeMode: "pull_only",
            syncTriggers: ["scheduled"],
          },
        }),
      ],
    })
    expect(errors.some((e) => e.includes("queueOnly cannot be used with remote replication"))).toBe(true)
  })
})
