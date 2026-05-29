import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  createSyncRouter,
  MemoryObjectStore,
  type SyncRouterOptions,
  type AuthResult,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"
import {
  MemoryQueue,
  createQueuingServerPlugin,
  type Queue,
  type QueueConfig,
} from "../src/index.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

function makeRouter(args: {
  collection: CollectionConfig
  queueCollections: Record<string, QueueConfig>
  queue?: Queue
}) {
  const store = new MemoryObjectStore(new Map())
  const queue = args.queue ?? new MemoryQueue()
  const config: SyncConfig = { version: 1, collections: [args.collection] }
  const opts: SyncRouterOptions = {
    store,
    config,
    roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["self"] }),
    plugins: [createQueuingServerPlugin({ queue, collections: args.queueCollections })],
  }
  return { app: createSyncRouter(opts), queue }
}

const jsonCol = (overrides: Partial<CollectionConfig> = {}): CollectionConfig => ({
  name: "events",
  storagePath: "users/{identity}/events",
  readRoles: ["self"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  ...overrides,
})

describe("queuing plugin — afterWrite publishes events", () => {
  it("publishes event after successful push", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol(),
      queueCollections: { events: { includeParams: true } },
    })

    await app.request("/push/users/user-1/events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const [subject, payload] = mem.messages[0]!
    expect(subject).toBe("events")
    const msg = JSON.parse(new TextDecoder().decode(payload))
    expect(msg.collection).toBe("events")
    expect(msg.hash).toHaveLength(64)
    expect(msg.params).toEqual({ identity: "user-1" })
  })

  it("includes body when includeBody is true", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false, includeBody: true } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { title: "Hello", value: 42 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.body).toEqual({ title: "Hello", value: 42 })
    expect(msg.params).toBeUndefined()
  })

  it("omits body by default", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.body).toBeUndefined()
  })

  it("includes both body and params when both flags set", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "users/{identity}/docs/{docId}" }),
      queueCollections: { docs: { includeParams: true, includeBody: true } },
    })

    await app.request("/push/users/user-1/docs/doc-99", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { content: "world" }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.body).toEqual({ content: "world" })
    expect(msg.params).toEqual({ identity: "user-1", docId: "doc-99" })
  })

  it("includes identity when includeIdentity is true", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false, includeIdentity: true } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    // roleResolver authenticates as "user-1" → WriteEvent.identity flows through.
    expect(msg.identity).toBe("user-1")
  })

  it("omits identity by default", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.identity).toBeUndefined()
  })

  it("default topic is the collection name; custom topic honored", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false, topic: "custom.topic" } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages[0]![0]).toBe("custom.topic")
  })

  it("binary collection with includeBody never emits body", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({
        name: "avatar",
        storagePath: "users/{identity}/avatar",
        allowedMimeTypes: ["image/png"],
      }),
      queueCollections: { avatar: { includeParams: false, includeBody: true } },
    })

    await app.request("/push/users/user-1/avatar", {
      method: "POST",
      headers: { "Content-Type": "image/png" },
      body: new Uint8Array([137, 80, 78, 71]),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.body).toBeUndefined()
    expect(msg.collection).toBe("avatar")
  })

  it("bundle collection with includeBody emits body", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({
        name: "prefs",
        storagePath: "users/{identity}/data",
        bundle: "userdata",
      }),
      queueCollections: { prefs: { includeParams: false, includeBody: true } },
    })

    await app.request("/push/users/user-1/data/prefs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { theme: "dark" }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.collection).toBe("prefs")
    expect(msg.body).toEqual({ theme: "dark" })
  })

  it("publishes nothing for collections absent from the plugin map", async () => {
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: {}, // "docs" not configured
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    expect((queue as MemoryQueue).messages).toHaveLength(0)
  })

  it("publish failure does not break the push response", async () => {
    let publishCalls = 0
    const failingQueue: Queue = {
      async publish() {
        publishCalls++
        throw new Error("NATS connection lost")
      },
    }
    const { app } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false } },
      queue: failingQueue,
    })

    const res = await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    expect(res.status).toBe(200)
    expect(publishCalls).toBe(1)
    const body = await res.json()
    expect(body.hash).toHaveLength(64)
  })
})

describe("queuing plugin — config edge cases", () => {
  it("treats an empty-string topic as unset and falls back to the collection name", async () => {
    // An empty-string topic is coalesced to the collection name (an empty broker
    // subject is a footgun). Both languages agree: TS `cfg.topic || event.collection`
    // (plugin.ts), Python `config.topic or event.collection` (publish.py). See test_plugin.py.
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "docs", storagePath: "docs/{docId}" }),
      queueCollections: { docs: { includeParams: false, topic: "" } },
    })

    await app.request("/push/docs/doc-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    expect((queue as MemoryQueue).messages[0]![0]).toBe("docs")
  })

  it("omits params when the collection storage path has no path parameters", async () => {
    // includeParams gate is `Object.keys(event.params).length > 0`, so an empty
    // params map (no `{…}` placeholders in storagePath) publishes no params field.
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "config", storagePath: "global/config" }),
      queueCollections: { config: { includeParams: true } },
    })

    await app.request("/push/global/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { x: 1 }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(mem.messages[0]![1]))
    expect(msg.params).toBeUndefined()
  })

  it("preserves unicode in the topic and body through the queue message", async () => {
    // Path segments are charset-restricted (non-ASCII is rejected at the door),
    // so unicode is probed on the reachable surfaces: the config topic and the
    // JSON body (keys and values).
    const { app, queue } = makeRouter({
      collection: jsonCol({ name: "rooms", storagePath: "rooms/{roomId}" }),
      queueCollections: {
        rooms: { includeParams: true, includeBody: true, topic: "更新.notify" },
      },
    })

    await app.request("/push/rooms/room-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { note: "Ñoño 🎉", "ключ": "значение" }, baseHash: null }),
    })

    const mem = queue as MemoryQueue
    expect(mem.messages).toHaveLength(1)
    const [subject, payload] = mem.messages[0]!
    expect(subject).toBe("更新.notify")
    const msg = JSON.parse(new TextDecoder().decode(payload))
    expect(msg.params.roomId).toBe("room-1")
    expect(msg.body.note).toBe("Ñoño 🎉")
    expect(msg.body["ключ"]).toBe("значение")
  })

  it("includes an explicit null body when handed one directly (unreachable defensive path)", async () => {
    // The TS gate is `if (event.body !== undefined)`, so a body of null is
    // published as body:null. The server NEVER emits body=null — route-builder.ts
    // sets WriteEvent.body only when the pushed data is a plain object, otherwise
    // leaves it undefined — so this branch is unreachable for a real document.
    // Python's gate is `if event.body is not None`, which OMITS a null/None body;
    // the difference is benign because neither path is reached in production.
    // Pinned (and flagged) so it's locked if WriteEvent population ever changes.
    // See test_plugin.py for the Python side.
    const queue = new MemoryQueue()
    const plugin = createQueuingServerPlugin({
      queue,
      collections: { docs: { includeParams: false, includeBody: true } },
    })
    await plugin.afterWrite!({
      collection: "docs",
      hash: "h",
      timestamp: 1,
      params: {},
      body: null as unknown as Record<string, unknown>,
    })

    expect(queue.messages).toHaveLength(1)
    const msg = JSON.parse(new TextDecoder().decode(queue.messages[0]![1]))
    expect(msg.body).toBeNull()
  })
})
