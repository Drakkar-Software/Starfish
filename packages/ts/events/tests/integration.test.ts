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

describe("createEventsServerPlugin", () => {
  it("returns 200 and stores a Parquet file on a valid push", async () => {
    const { app, store } = makeApp()

    const res = await app.request("/push/events/myapp/batch-1", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { events: [sampleEvent] }, baseHash: null }),
    })

    expect(res.status).toBe(200)
    const body = (await res.json()) as { hash: string }
    expect(typeof body.hash).toBe("string")
    expect(body.hash.length).toBe(64) // 32-byte SHA-256 as hex

    // The stored key should exist in the object store.
    const stored = await store.getBytes!("events/myapp/batch-1.parquet")
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

  it("serves Parquet bytes on GET pull for JSON events collection", async () => {
    const { app } = makeApp()

    const pushRes = await app.request("/push/events/myapp/batch-pull", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { events: [sampleEvent] }, baseHash: null }),
    })
    expect(pushRes.status).toBe(200)

    const pullRes = await app.request("/pull/events/myapp/batch-pull", { method: "GET" })
    expect(pullRes.status).toBe(200)
    expect(pullRes.headers.get("content-type")).toBe("application/vnd.apache.parquet")
    const buf = await pullRes.arrayBuffer()
    expect(new Uint8Array(buf).slice(0, 4)).toEqual(new Uint8Array([0x50, 0x41, 0x52, 0x31]))
  })

  it("pull returns 304 on matching ETag (conditional GET)", async () => {
    const { app } = makeApp()

    await app.request("/push/events/myapp/batch-etag", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { events: [sampleEvent] }, baseHash: null }),
    })

    const first = await app.request("/pull/events/myapp/batch-etag", { method: "GET" })
    expect(first.status).toBe(200)
    const etag = first.headers.get("etag")!
    expect(etag).toBeTruthy()

    const cond = await app.request("/pull/events/myapp/batch-etag", {
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

    const res = await app.request("/push/events/myapp/batch-empty", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { events: [] }, baseHash: null }),
    })

    expect(res.status).toBe(200)
    // Parquet file still written (zero rows)
    const stored = await store.getBytes!("events/myapp/batch-empty.parquet")
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

    const res = await app.request("/push/events/myapp/batch-multi", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ data: { events }, baseHash: null }),
    })

    expect(res.status).toBe(200)
    const stored = await store.getBytes!("events/myapp/batch-multi.parquet")
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
})
