/**
 * Append/checkpoint-aware batch pull tests.
 *
 * Tests the `appendParams` query parameter that routes each batch entry to
 * `handleAppendOnlyPull` and returns a bounded tail of the append-only log.
 *
 * Key invariants tested:
 *  - last=1 returns only the newest element
 *  - last=N returns the N newest elements
 *  - since=T filters strictly (ts > T); since=0 returns all
 *  - since + last combined: filter then tail
 *  - full:true rejected 400 (whole-request DoS guard)
 *  - no bound params → pull_bound_required per-entry
 *  - non-append-only collection + appendParams → append_params_not_supported
 *  - mixed: append + non-append collections in one request
 *  - non-default appendField (e.g. "entries")
 *  - maxPullLimit clamps requested last
 *  - limit (alias of last) works the same way
 *  - per-entry different bounds in same collection
 *  - missing appendParams entry (index beyond array) → falls back to full-doc pull
 *  - field-read filter applied on append branch
 *  - invalid appendParams JSON → 400
 *  - invalid appendParams top-level type → 400
 */
import { describe, it, expect } from "vitest"
import { readFileSync } from "fs"
import { join } from "path"
import { createSyncRouter, type SyncRouterOptions } from "../../src/router/route-builder.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { webcrypto } from "node:crypto"
import type { CollectionConfig } from "../../src/config/schema.js"

configurePlatform({
  crypto: webcrypto as any,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

// ── helpers ───────────────────────────────────────────────────────────────────

/** Build and seed a router with deterministic append-only data. */
function makeRouter(
  collections: CollectionConfig[],
  fixtures: Record<string, Record<string, unknown>>,
  opts: Partial<SyncRouterOptions> = {},
) {
  const raw = new Map<string, string>()
  for (const [key, val] of Object.entries(fixtures)) {
    // Append-only docs are stored as { data: { <field>: [...] }, hash, ts }
    raw.set(key, JSON.stringify({ data: val, hash: `h-${key}`, ts: 9999 }))
  }
  const store = new MemoryObjectStore(raw)
  const app = createSyncRouter({
    store,
    config: { version: 1, collections },
    roleResolver: async () => ({ identity: "user-1", roles: [] }),
    ...opts,
  })
  return { app, store }
}

const eventsCol: CollectionConfig = {
  name: "events",
  storagePath: "rooms/{roomId}/events",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  appendOnly: { type: "by_timestamp", field: "items", persist: true, allowFull: true },
}

const strictEventsCol: CollectionConfig = {
  name: "strictevents",
  storagePath: "rooms/{roomId}/strictevents",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  appendOnly: {
    type: "by_timestamp",
    field: "items",
    persist: true,
    allowFull: false,
    maxPullLimit: 2,
  },
}

const feedCol: CollectionConfig = {
  name: "feed",
  storagePath: "users/{userId}/feed",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  appendOnly: { type: "by_timestamp", field: "entries", persist: true, allowFull: true },
}

const notesCol: CollectionConfig = {
  name: "notes",
  storagePath: "users/{userId}/notes",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  // NOT appendOnly — regular sync doc
}

const secretsCol: CollectionConfig = {
  name: "secrets",
  storagePath: "users/{userId}/secrets",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 1_000_000,
  allowedMimeTypes: ["application/json"],
  appendOnly: { type: "by_timestamp", field: "items", persist: true, allowFull: true },
  fieldPermissions: {
    secretField: { readRoles: ["admin"] }, // only admins may read this field
  },
}

/** Fixture data for standard 5-element rooms/{roomId}/events documents. */
const ROOM1_ITEMS = [
  { ts: 100, data: { text: "first" } },
  { ts: 200, data: { text: "second" } },
  { ts: 300, data: { text: "third" } },
  { ts: 400, data: { text: "fourth" } },
  { ts: 500, data: { text: "fifth" } },
]
const ROOM2_ITEMS = [
  { ts: 10, data: { text: "a" } },
  { ts: 20, data: { text: "b" } },
]

function batchUrl(
  collections: string[],
  paramMap: Record<string, Record<string, string>[]>,
  appendMap?: Record<string, Record<string, unknown>[]>,
) {
  let url = `/batch/pull?collections=${collections.join(",")}`
  url += `&params=${encodeURIComponent(JSON.stringify(paramMap))}`
  if (appendMap) {
    url += `&appendParams=${encodeURIComponent(JSON.stringify(appendMap))}`
  }
  return url
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("batch pull appendParams — bounded-tail reads", () => {
  it("last=1 returns only the newest element", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ last: 1 }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    expect(items).toHaveLength(1)
    expect(items[0].ts).toBe(500)
  })

  it("last=3 returns the 3 newest elements", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ last: 3 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    expect(items).toHaveLength(3)
    expect(items[0].ts).toBe(300)
    expect(items[2].ts).toBe(500)
  })

  it("since=200 (checkpoint) strictly excludes ts≤200 — requires last bound", async () => {
    // since maps to checkpoint; must be paired with last/limit since full is disallowed.
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ since: 200, last: 100 }] }, // since=checkpoint=200, bound with last=100
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    // checkpoint=200 → ts>200 → third(300), fourth(400), fifth(500)
    expect(items).toHaveLength(3)
    expect(items[0].ts).toBe(300)
    expect(items[2].ts).toBe(500)
  })

  it("since=0 (explicit checkpoint=0) without last returns all elements", async () => {
    // checkpointParam="0" is non-null, so pull_bound_required is NOT triggered.
    // checkpoint=0 means "from the beginning" — returns all items in the log.
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ since: 0 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    expect(items).toHaveLength(5)
  })

  it("missing since+last+limit with appendOpts={} → pull_bound_required (no explicit checkpoint)", async () => {
    // An empty appendParams entry passes checkpointParam=null, lastParam=null →
    // triggers pull_bound_required (parity with the standalone handler).
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{}] },
    )
    const res = await app.request(url)
    const body = await res.json()
    expect(body.collections.events[0].error).toBe("pull_bound_required")
  })

  it("since + last combined: checkpoint=100 (ts>100) then tail last=2 → (400, 500)", async () => {
    // since=100 → checkpoint=100 → elements 200,300,400,500 (ts>100)
    // last=2 → take last 2 of those → 400, 500
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ since: 100, last: 2 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    expect(items).toHaveLength(2)
    expect(items[0].ts).toBe(400)
    expect(items[1].ts).toBe(500)
  })

  it("full:true in appendParams is rejected 400 (whole-request DoS guard)", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ full: true }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(400)
  })

  it("no bound in appendParams entry → pull_bound_required per-entry", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{}] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.events[0].error).toBe("pull_bound_required")
  })

  it("non-append-only collection with appendParams → append_params_not_supported", async () => {
    const { app } = makeRouter([notesCol], {
      "users/alice/notes": { body: "hi" },
    })
    const url = batchUrl(
      ["notes"],
      { notes: [{ userId: "alice" }] },
      { notes: [{ last: 1 }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.notes[0].error).toBe("append_params_not_supported")
  })

  it("mixed: append collection (events) and regular collection (notes) in one request", async () => {
    const { app } = makeRouter([eventsCol, notesCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
      "users/alice/notes": { body: "a note" },
    })
    const url = batchUrl(
      ["events", "notes"],
      { events: [{ roomId: "room-1" }], notes: [{ userId: "alice" }] },
      { events: [{ last: 1 }] }, // only events gets appendParams
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    // events → bounded tail
    expect(body.collections.events[0].data?.items).toHaveLength(1)
    expect(body.collections.events[0].data?.items[0].ts).toBe(500)
    // notes → full doc (no appendParams)
    expect(body.collections.notes[0].data?.body).toBe("a note")
  })

  it("non-default appendField ('entries') is used from collection config", async () => {
    const { app } = makeRouter([feedCol], {
      "users/alice/feed": {
        entries: [
          { ts: 1000, data: { post: "hello" } },
          { ts: 2000, data: { post: "world" } },
        ],
      },
    })
    const url = batchUrl(
      ["feed"],
      { feed: [{ userId: "alice" }] },
      { feed: [{ last: 1 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    // Result must live under "entries", not "items"
    expect(body.collections.feed[0].data?.entries).toHaveLength(1)
    expect(body.collections.feed[0].data?.entries[0].ts).toBe(2000)
    expect(body.collections.feed[0].data?.items).toBeUndefined()
  })

  it("maxPullLimit clamps requested last (strictevents: maxPullLimit=2)", async () => {
    const { app } = makeRouter([strictEventsCol], {
      "rooms/room-1/strictevents": {
        items: [
          { ts: 100, data: { msg: "x" } },
          { ts: 200, data: { msg: "y" } },
          { ts: 300, data: { msg: "z" } },
        ],
      },
    })
    const url = batchUrl(
      ["strictevents"],
      { strictevents: [{ roomId: "room-1" }] },
      { strictevents: [{ last: 999 }] }, // requests 999, clamped to 2
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.strictevents[0].data?.items
    expect(items).toHaveLength(2) // clamped
    expect(items[0].ts).toBe(200)
    expect(items[1].ts).toBe(300)
  })

  it("per-entry different last bounds in same batch collection", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
      "rooms/room-2/events": { items: ROOM2_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }, { roomId: "room-2" }] },
      { events: [{ last: 2 }, { last: 1 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    const entries = body.collections.events
    // room-1: last 2 → 400, 500
    expect(entries[0].data?.items).toHaveLength(2)
    expect(entries[0].data?.items[0].ts).toBe(400)
    expect(entries[0].data?.items[1].ts).toBe(500)
    // room-2: last 1 → 20
    expect(entries[1].data?.items).toHaveLength(1)
    expect(entries[1].data?.items[0].ts).toBe(20)
  })

  it("appendParams with fewer entries than params is rejected 400 (length-equality guard)", async () => {
    // appendParams must have exactly as many entries as params for the same collection.
    // A shorter array is rejected with a whole-request 400 to prevent silent fall-through.
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
      "rooms/room-2/events": { items: ROOM2_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }, { roomId: "room-2" }] },
      { events: [{ last: 1 }] }, // only one entry for two params → length mismatch
    )
    const res = await app.request(url)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/length mismatch/i)
  })

  it("restricted fields inside append elements are stripped", async () => {
    // secretsCol has fieldPermissions.secretField: readRoles:["admin"]
    // caller has no admin role → secretField must be absent from every element's .data
    const { app } = makeRouter([secretsCol], {
      "users/alice/secrets": {
        items: [
          { ts: 100, data: { text: "public text", secretField: "hidden-1" } },
          { ts: 200, data: { text: "also public", secretField: "hidden-2" } },
        ],
      },
    })
    const url = batchUrl(
      ["secrets"],
      { secrets: [{ userId: "alice" }] },
      { secrets: [{ since: 0 }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    const items = body.collections.secrets[0].data?.items
    expect(items).toBeDefined()
    expect(items).toHaveLength(2)
    // Non-restricted field must be present in every element
    for (const item of items) {
      expect(item.data).toHaveProperty("text")
      // Restricted field must be absent from every element's data
      expect(item.data).not.toHaveProperty("secretField")
    }
    expect(body.collections.secrets[0].error).toBeUndefined()
  })

  it("invalid appendParams JSON returns 400 (whole request)", async () => {
    const { app } = makeRouter([eventsCol], {})
    const res = await app.request(
      `/batch/pull?collections=events&params=${encodeURIComponent(JSON.stringify({ events: [{ roomId: "room-1" }] }))}&appendParams=NOT_JSON`,
    )
    expect(res.status).toBe(400)
  })

  it("appendParams as JSON array (not object) returns 400", async () => {
    const { app } = makeRouter([eventsCol], {})
    const res = await app.request(
      `/batch/pull?collections=events&params=${encodeURIComponent(JSON.stringify({ events: [{ roomId: "room-1" }] }))}&appendParams=${encodeURIComponent("[1,2,3]")}`,
    )
    expect(res.status).toBe(400)
  })

  it("appendParams with non-array value for collection returns 400", async () => {
    const { app } = makeRouter([eventsCol], {})
    const res = await app.request(
      `/batch/pull?collections=events&params=${encodeURIComponent(JSON.stringify({ events: [{ roomId: "room-1" }] }))}&appendParams=${encodeURIComponent(JSON.stringify({ events: { last: 1 } }))}`,
    )
    expect(res.status).toBe(400)
  })

  it("appendParams without matching params collection: entry uses auto-filled params", async () => {
    // The "feed" collection does not need params (auto-fills identity).
    // If appendParams specifies it without params, it should still work for bound pull.
    const userFeedCol: CollectionConfig = {
      name: "myfeed",
      storagePath: "users/{identity}/feed",
      readRoles: ["public"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
      appendOnly: { type: "by_timestamp", field: "items", persist: true, allowFull: true },
    }
    const { app } = makeRouter([userFeedCol], {
      "users/user-1/feed": {
        items: [
          { ts: 10, data: { v: "a" } },
          { ts: 20, data: { v: "b" } },
        ],
      },
    })
    // No params for "myfeed" → server auto-fills {identity} = "user-1"
    const url = `/batch/pull?collections=myfeed&appendParams=${encodeURIComponent(JSON.stringify({ myfeed: [{ last: 1 }] }))}`
    const res = await app.request(url)
    const body = await res.json()
    expect(body.collections.myfeed[0].error).toBeUndefined()
    expect(body.collections.myfeed[0].data?.items).toHaveLength(1)
    expect(body.collections.myfeed[0].data?.items[0].ts).toBe(20)
  })

  it("limit alias works the same as last", async () => {
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ limit: 2 }] }, // limit is an alias for last
    )
    const res = await app.request(url)
    const body = await res.json()
    const items = body.collections.events[0].data?.items
    expect(items).toHaveLength(2)
    expect(items[0].ts).toBe(400)
    expect(items[1].ts).toBe(500)
  })

  it("two collections, each with appendParams, in one request", async () => {
    const { app } = makeRouter([eventsCol, feedCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
      "users/alice/feed": {
        entries: [
          { ts: 1000, data: { post: "hello" } },
          { ts: 2000, data: { post: "world" } },
        ],
      },
    })
    const url = batchUrl(
      ["events", "feed"],
      { events: [{ roomId: "room-1" }], feed: [{ userId: "alice" }] },
      { events: [{ last: 1 }], feed: [{ last: 1 }] },
    )
    const res = await app.request(url)
    const body = await res.json()
    expect(body.collections.events[0].data?.items).toHaveLength(1)
    expect(body.collections.events[0].data?.items[0].ts).toBe(500)
    expect(body.collections.feed[0].data?.entries).toHaveLength(1)
    expect(body.collections.feed[0].data?.entries[0].ts).toBe(2000)
  })

  // ── G14: additional tests ──────────────────────────────────────────────────

  it("float bound in since is rejected with 400", async () => {
    // since:1.5 is not an integer — the server must reject the whole request.
    const { app } = makeRouter([eventsCol], {
      "rooms/room-1/events": { items: ROOM1_ITEMS },
    })
    const url = batchUrl(
      ["events"],
      { events: [{ roomId: "room-1" }] },
      { events: [{ since: 1.5 }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(400)
  })

  it("aggregate append-element budget exceeded returns 400", async () => {
    // maxBatchAppendElements defaults to 5000.
    // Create a collection whose maxPullLimit is 1000, then request 6 entries × last=1000 = 6000 > 5000.
    const bigLimitCol: CollectionConfig = {
      name: "bigevents",
      storagePath: "rooms/{roomId}/bigevents",
      readRoles: ["public"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
      appendOnly: { type: "by_timestamp", field: "items", persist: true, allowFull: true, maxPullLimit: 1000 },
    }
    // Seed 6 rooms so we have 6 param entries
    const fixtures: Record<string, Record<string, unknown>> = {}
    for (let i = 1; i <= 6; i++) {
      fixtures[`rooms/room-${i}/bigevents`] = { items: [{ ts: i, data: { x: i } }] }
    }
    const { app } = makeRouter([bigLimitCol], fixtures)
    const paramsList = Array.from({ length: 6 }, (_, i) => ({ roomId: `room-${i + 1}` }))
    const appendList = Array.from({ length: 6 }, () => ({ last: 1000 }))
    const url = batchUrl(
      ["bigevents"],
      { bigevents: paramsList },
      { bigevents: appendList },
    )
    const res = await app.request(url)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toMatch(/budget exceeded/i)
  })

  it("_keyring collection in batch is Forbidden even with public readRoles", async () => {
    // batchKeyDenySuffixes includes "_keyring" by default.
    // A collection whose storagePath resolves to a _keyring key must be blocked.
    const keyringCol: CollectionConfig = {
      name: "keyring",
      storagePath: "users/{userId}/_keyring",
      readRoles: ["public"],
      writeRoles: ["self"],
      encryption: "none",
      maxBodyBytes: 1_000_000,
      allowedMimeTypes: ["application/json"],
    }
    const { app } = makeRouter([keyringCol], {
      "users/alice/_keyring": { key: "super-secret" },
    })
    const url = batchUrl(
      ["keyring"],
      { keyring: [{ userId: "alice" }] },
    )
    const res = await app.request(url)
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.collections.keyring[0].error).toBe("Forbidden")
    expect(body.collections.keyring[0].data).toBeUndefined()
  })
})

// ── G13: conformance vectors ───────────────────────────────────────────────────

describe("conformance vectors — batch-pull-append", () => {
  const vectorPath = join(__dirname, "../../../../../tests/test-vectors/batch-pull-append.json")
  const vectors = JSON.parse(readFileSync(vectorPath, "utf8")) as {
    collections: CollectionConfig[]
    fixtures: Record<string, Record<string, unknown>>
    cases: Array<{
      id: string
      description?: string
      caller?: string
      capScope?: string
      collections: string[]
      params?: Record<string, Record<string, unknown>[]>
      appendParams?: Record<string, Record<string, unknown>[]>
      rawAppendParams?: string
      expectedStatus?: number
      expected?: Record<string, Array<{
        outcome: "ok" | "error"
        error?: string
        appendField?: string
        count?: number
        firstTs?: number
        lastTs?: number
        fullDoc?: boolean
        dataFields?: Record<string, unknown>
      }>>
    }>
  }

  /**
   * Build a router from the vector's shared collections + fixtures.
   * The vector uses role-resolver returning caller identity with no extra roles.
   */
  function makeVectorRouter(caller: string, extraOpts: Partial<SyncRouterOptions> = {}) {
    const raw = new Map<string, string>()
    for (const [key, val] of Object.entries(vectors.fixtures)) {
      raw.set(key, JSON.stringify({ data: val, hash: `h-${key}`, ts: 9999 }))
    }
    const store = new MemoryObjectStore(raw)
    return createSyncRouter({
      store,
      config: {
        version: 1,
        collections: vectors.collections.map((col) => ({
          ...col,
          maxBodyBytes: col.maxBodyBytes ?? 1_000_000,
          allowedMimeTypes: col.allowedMimeTypes ?? ["application/json"],
        })),
      },
      roleResolver: async () => ({ identity: caller ?? "alice", roles: [] }),
      ...extraOpts,
    })
  }

  for (const c of vectors.cases) {
    it(`vector: ${c.id}`, async () => {
      // aggregate_budget_exceeded requires maxBatchAppendElements=5 per the vector note
      const extraOpts: Partial<SyncRouterOptions> =
        c.id === "aggregate_budget_exceeded" ? { maxBatchAppendElements: 5 } : {}
      const app = makeVectorRouter(c.caller ?? "alice", extraOpts)

      // Build URL
      let url = `/batch/pull?collections=${c.collections.join(",")}`
      if (c.params) {
        url += `&params=${encodeURIComponent(JSON.stringify(c.params))}`
      }
      if (c.rawAppendParams != null) {
        // Raw (possibly malformed) appendParams — encode as-is
        url += `&appendParams=${encodeURIComponent(c.rawAppendParams)}`
      } else if (c.appendParams != null) {
        url += `&appendParams=${encodeURIComponent(JSON.stringify(c.appendParams))}`
      }

      const res = await app.request(url)

      // Whole-request status assertions
      if (c.expectedStatus != null) {
        expect(res.status, `${c.id}: HTTP status`).toBe(c.expectedStatus)
        return
      }

      // Per-collection outcome assertions
      expect(res.status, `${c.id}: HTTP status`).toBe(200)
      const body = await res.json()

      if (c.expected) {
        for (const [colName, colExpected] of Object.entries(c.expected)) {
          const entries: unknown[] = body.collections[colName]
          expect(entries, `${c.id}: collections.${colName} should be an array`).toBeInstanceOf(Array)
          expect(entries.length, `${c.id}: collections.${colName} entry count`).toBe(colExpected.length)

          for (let i = 0; i < colExpected.length; i++) {
            const exp = colExpected[i]
            const got = entries[i] as Record<string, unknown>

            if (exp.outcome === "error") {
              expect(got.error, `${c.id}: collections.${colName}[${i}].error`).toBe(exp.error)
            } else {
              // outcome === "ok"
              expect(got.error, `${c.id}: collections.${colName}[${i}] should not have error`).toBeUndefined()

              if (exp.fullDoc) {
                // Full-doc pull: data should exist but we don't inspect append structure
                expect(got.data, `${c.id}: collections.${colName}[${i}].data`).toBeDefined()
              } else if (exp.appendField != null) {
                const data = got.data as Record<string, unknown>
                const items = data[exp.appendField] as Array<{ ts: number }>
                expect(items, `${c.id}: collections.${colName}[${i}].data.${exp.appendField}`).toBeInstanceOf(Array)

                if (exp.count != null) {
                  expect(items.length, `${c.id}: collections.${colName}[${i}] item count`).toBe(exp.count)
                }
                if (exp.firstTs != null && items.length > 0) {
                  expect(items[0].ts, `${c.id}: collections.${colName}[${i}] first ts`).toBe(exp.firstTs)
                }
                if (exp.lastTs != null && items.length > 0) {
                  expect(items[items.length - 1].ts, `${c.id}: collections.${colName}[${i}] last ts`).toBe(exp.lastTs)
                }
              }

              if (exp.dataFields != null) {
                const data = got.data as Record<string, unknown>
                for (const [field, value] of Object.entries(exp.dataFields)) {
                  expect(data[field], `${c.id}: collections.${colName}[${i}].data.${field}`).toBe(value)
                }
              }
            }
          }
        }
      }
    })
  }
})
