/**
 * Integration tests for createEventsServerPlugin.
 *
 * Uses a real createSyncRouter + MemoryObjectStore to exercise the full
 * interceptPush dispatch path, matching the pattern in starfish-replica.
 */
import { describe, it, expect, beforeAll } from "vitest"
import { createEventsServerPlugin } from "../src/plugin.js"
import { createSyncRouter, MemoryObjectStore } from "@drakkar.software/starfish-server"
import type { SyncConfig } from "@drakkar.software/starfish-server"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import { parquetReadObjects } from "hyparquet"

// Configure the platform crypto so the router and hash helpers work in Node.
configurePlatform({
  crypto: webcrypto as unknown as Crypto,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

/** Wrap an ArrayBuffer as an AsyncBuffer for hyparquet. */
function toAsyncBuffer(buf: ArrayBuffer) {
  return {
    byteLength: buf.byteLength,
    slice: (start: number, end?: number) => buf.slice(start, end),
  }
}

const COLLECTION = "events"
const STORAGE_PATH = "events/{app}/{batchId}"

const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: COLLECTION,
      storagePath: STORAGE_PATH,
      readRoles: ["public"],
      writeRoles: ["public"],
      encryption: "none",
      maxBodyBytes: 8_000_000,
      // JSON-typed so interceptPush receives a populated rawBody
      allowedMimeTypes: ["application/json"],
      // Lets the dashboard/tests discover server-assigned batch ids via /list.
      listable: true,
    },
  ],
}

function makeApp() {
  const store = new MemoryObjectStore()
  const plugin = createEventsServerPlugin({ store, collection: COLLECTION, storagePath: STORAGE_PATH })
  const app = createSyncRouter({
    store,
    config,
    roleResolver: async () => ({ identity: "u", roles: ["public"] }),
    plugins: [plugin],
  })
  return { app, store }
}

const sampleEvent = {
  event_type: "capture",
  event: "button_clicked",
  distinct_id: "user-abc",
  anonymous_id: "anon-xyz",
  ts: "2024-06-01T10:00:00.000Z",
  message_id: "msg-001",
  properties: '{"label":"Submit"}',
  context: '{"platform":"web"}',
  dt: "2024-06-01",
}

async function pushSample(app: ReturnType<typeof makeApp>["app"], clientBatchId: string, events = [sampleEvent]) {
  return app.request(`/push/events/myapp/${clientBatchId}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ data: { events }, baseHash: null }),
  })
}

/** List the events/myapp collection and return the raw stored filenames (with .parquet). */
async function listStoredFiles(app: ReturnType<typeof makeApp>["app"], after?: string) {
  const qs = after ? `?limit=10&after=${encodeURIComponent(after)}` : "?limit=10"
  const res = await app.request(`/list/events/myapp${qs}`)
  expect(res.status).toBe(200)
  return (await res.json()) as { items: string[]; hasMore: boolean }
}

describe("createEventsServerPlugin", () => {
  it("stores a Parquet file at a server-assigned sortable id, ignoring the client's batchId", async () => {
    const { app, store } = makeApp()

    const res = await pushSample(app, "client-supplied-id")

    expect(res.status).toBe(200)
    const body = (await res.json()) as { hash: string }
    expect(typeof body.hash).toBe("string")
    expect(body.hash.length).toBe(64) // 32-byte SHA-256 as hex

    // The client's own id is NOT used as the storage key.
    expect(await store.getBytes!("events/myapp/client-supplied-id.parquet")).toBeNull()

    // Discover the actual stored id via /list — the same path the dashboard uses.
    const { items } = await listStoredFiles(app)
    expect(items).toHaveLength(1)
    const storedFile = items[0]!
    expect(storedFile).toMatch(/^\d{13}-\d{4}-[0-9a-f]{6}\.parquet$/)

    const stored = await store.getBytes!(`events/myapp/${storedFile}`)
    expect(stored).not.toBeNull()
    expect(stored!.contentType).toBe("application/vnd.apache.parquet")

    // Verify it is valid Parquet and decodes to the expected rows.
    const asyncBuf = toAsyncBuffer(stored!.body.buffer as ArrayBuffer)
    const rows = await parquetReadObjects({ file: asyncBuf })
    expect(rows).toHaveLength(1)
    expect(rows[0]?.["event"]).toBe("button_clicked")
    expect(rows[0]?.["event_type"]).toBe("capture")
    expect(rows[0]?.["anonymous_id"]).toBe("anon-xyz")
    // received_at stamped by plugin
    expect(typeof rows[0]?.["received_at"]).toBe("string")
    // distinct_id preserved (PII already sanitized by SunGlasses SDK before push)
    expect(rows[0]?.["distinct_id"]).toBe("user-abc")
  })

  it("serves Parquet bytes on GET pull, addressed by the id learned from /list", async () => {
    const { app } = makeApp()

    const pushRes = await pushSample(app, "client-id-ignored")
    expect(pushRes.status).toBe(200)

    const { items } = await listStoredFiles(app)
    expect(items).toHaveLength(1)
    const batchId = items[0]!.replace(/\.parquet$/, "")

    const pullRes = await app.request(`/pull/events/myapp/${batchId}`, { method: "GET" })
    expect(pullRes.status).toBe(200)
    expect(pullRes.headers.get("content-type")).toBe("application/vnd.apache.parquet")
    const buf = await pullRes.arrayBuffer()
    expect(new Uint8Array(buf).slice(0, 4)).toEqual(new Uint8Array([0x50, 0x41, 0x52, 0x31]))
  })

  it("pull returns 304 on matching ETag (conditional GET)", async () => {
    const { app } = makeApp()

    await pushSample(app, "client-id-ignored")
    const { items } = await listStoredFiles(app)
    const batchId = items[0]!.replace(/\.parquet$/, "")

    const first = await app.request(`/pull/events/myapp/${batchId}`, { method: "GET" })
    expect(first.status).toBe(200)
    const etag = first.headers.get("etag")!
    expect(etag).toBeTruthy()

    const cond = await app.request(`/pull/events/myapp/${batchId}`, {
      method: "GET",
      headers: { "if-none-match": etag },
    })
    expect(cond.status).toBe(304)
  })

  it("pull falls through to JSON sync response when no batch was pushed", async () => {
    // The sync protocol returns 200 with an empty-data envelope for missing documents.
    const { app } = makeApp()
    const pullRes = await app.request("/pull/events/myapp/nonexistent-batch", { method: "GET" })
    expect(pullRes.status).toBe(200)
    const body = await pullRes.json()
    // JSON sync response: empty data object indicates no document written yet.
    expect(typeof body).toBe("object")
    expect(body.hash).toBeFalsy()
  })

  it("handles an empty events array gracefully", async () => {
    const { app, store } = makeApp()

    const res = await pushSample(app, "client-id-ignored", [])

    expect(res.status).toBe(200)
    // Parquet file still written (zero rows)
    const { items } = await listStoredFiles(app)
    expect(items).toHaveLength(1)
    const stored = await store.getBytes!(`events/myapp/${items[0]}`)
    expect(stored).not.toBeNull()
    const rows = await parquetReadObjects({ file: toAsyncBuffer(stored!.body.buffer as ArrayBuffer) })
    expect(rows).toHaveLength(0)
  })

  it("handles multiple events in a single batch", async () => {
    const { app, store } = makeApp()

    const events = [
      { ...sampleEvent, message_id: "msg-001", event: "page_viewed" },
      { ...sampleEvent, message_id: "msg-002", event: "button_clicked" },
      { ...sampleEvent, message_id: "msg-003", event: "form_submitted" },
    ]

    const res = await pushSample(app, "client-id-ignored", events)

    expect(res.status).toBe(200)
    const { items } = await listStoredFiles(app)
    expect(items).toHaveLength(1)
    const stored = await store.getBytes!(`events/myapp/${items[0]}`)
    expect(stored).not.toBeNull()
    const rows = await parquetReadObjects({ file: toAsyncBuffer(stored!.body.buffer as ArrayBuffer) })
    expect(rows).toHaveLength(3)
    expect(rows.map((r) => r["event"])).toEqual(["page_viewed", "button_clicked", "form_submitted"])
  })

  it("returns 400 on malformed JSON body", async () => {
    const { app } = makeApp()

    const res = await app.request("/push/events/myapp/batch-bad", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json at all",
    })

    expect(res.status).toBe(400)
  })

  it("does not intercept pushes to other collections", async () => {
    const store = new MemoryObjectStore()
    // Config with two collections
    const twoColConfig: SyncConfig = {
      version: 1,
      collections: [
        ...config.collections,
        {
          name: "other",
          storagePath: "other/{id}",
          readRoles: ["public"],
          writeRoles: ["public"],
          encryption: "none",
          maxBodyBytes: 1_000_000,
          allowedMimeTypes: ["application/json"],
        },
      ],
    }
    const plugin = createEventsServerPlugin({ store, collection: COLLECTION, storagePath: STORAGE_PATH })
    const app = createSyncRouter({
      store,
      config: twoColConfig,
      roleResolver: async () => ({ identity: "u", roles: ["public"] }),
      plugins: [plugin],
    })

    // Push to "other" — plugin should proceed, default JSON write happens
    const res = await app.request("/push/other/123", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { foo: "bar" }, baseHash: null }),
    })

    expect(res.status).toBe(200)
    // No Parquet file written for "other"
    const noParquet = await store.getBytes?.("other/123.parquet")
    expect(noParquet).toBeNull()
    // But JSON was written by the default handler
    const json = await store.getString("other/123")
    expect(json).not.toBeNull()
  })

  it("throws at construction when the store lacks putBytes", () => {
    const storeLite = {
      getString: async () => null,
      put: async () => {},
      listKeys: async () => [],
      delete: async () => {},
      deleteMany: async () => {},
      // no putBytes
    }
    expect(() =>
      createEventsServerPlugin({ store: storeLite, collection: "events", storagePath: "events/{x}/{y}" }),
    ).toThrow("putBytes")
  })

  it("throws at construction when storagePath doesn't end with a {param} segment", () => {
    const store = new MemoryObjectStore()
    expect(() =>
      createEventsServerPlugin({ store, collection: "events", storagePath: "events/{app}/fixed" }),
    ).toThrow("{param}")
  })

  it("assigns strictly ascending sortable ids across successive pushes, listed in insertion order", async () => {
    const { app } = makeApp()

    for (let i = 0; i < 5; i++) {
      const res = await pushSample(app, "ignored")
      expect(res.status).toBe(200)
    }

    const { items, hasMore } = await listStoredFiles(app)
    expect(hasMore).toBe(false)
    expect(items).toHaveLength(5)
    // Ascending lexicographic order from the store IS the insertion (chronological) order.
    expect(items).toEqual([...items].sort())
    // No duplicate ids even for pushes issued back-to-back within the same tick.
    expect(new Set(items).size).toBe(5)
  })

  it("resumes /list via `after` so only batches pushed since the cursor are returned", async () => {
    const { app } = makeApp()

    await pushSample(app, "ignored-1")
    const { items: firstItems } = await listStoredFiles(app)
    expect(firstItems).toHaveLength(1)
    const cursor = firstItems[0]!

    // No new pushes yet — resuming from the cursor returns nothing.
    const idle = await listStoredFiles(app, cursor)
    expect(idle.items).toHaveLength(0)
    expect(idle.hasMore).toBe(false)

    await pushSample(app, "ignored-2")

    const resumed = await listStoredFiles(app, cursor)
    expect(resumed.items).toHaveLength(1)
    expect(resumed.items[0]).not.toBe(cursor)
  })
})
