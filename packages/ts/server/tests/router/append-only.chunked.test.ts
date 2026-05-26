// Precise tests for the two opt-in append-only scaling knobs:
//   - `maxItems` — reject appends past a cap (409 append_limit_exceeded).
//   - `chunkSize` — segmented storage (sealed chunks + head), bounded-cost append.
//
// The load-bearing claim is wire-contract parity: a `chunkSize` collection must
// return byte-identical pull responses AND the identical `hash` to a single-doc
// collection for the same append sequence. Most cases are one-liners over a shared
// parity helper that runs the same sequence against both layouts.

import { describe, it, expect } from "vitest"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { appendItem, appendSegPrefix, type AppendOptions } from "../../src/protocol/push.js"
import { handleAppendOnlyPull } from "../../src/router/helpers.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import { FilesystemObjectStore } from "../../src/storage/filesystem.js"
import { createSyncRouter, type SyncRouterOptions, type AuthResult } from "../../src/router/route-builder.js"
import type { ObjectStore } from "../../src/storage/base.js"
import type { SyncConfig, CollectionConfig } from "../../src/config/schema.js"

configurePlatform({
  crypto: webcrypto as unknown as Crypto,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

const FIELD = "items"
type Seq = Array<[Record<string, unknown>, number]> // [item, explicit ts]

/** Build a sequence of `count` elements with ts = 10, 20, … (strictly increasing). */
function seqOf(count: number): Seq {
  return Array.from({ length: count }, (_, i) => [{ n: i + 1 }, (i + 1) * 10] as [Record<string, unknown>, number])
}

/** Append a sequence; return the final element's hash (or throw on a conflict). */
async function runSeq(store: ObjectStore, key: string, seq: Seq, opts: AppendOptions): Promise<string> {
  let hash = ""
  for (const [item, ts] of seq) {
    const out = await appendItem(store, key, item, FIELD, ts, opts)
    if (!("hash" in out)) throw new Error(`unexpected append outcome: ${JSON.stringify(out)}`)
    hash = out.hash
  }
  return hash
}

async function pull(store: ObjectStore, key: string, q: { checkpoint?: number; last?: number } = {}): Promise<unknown[]> {
  const res = await handleAppendOnlyPull(
    key,
    store,
    q.checkpoint != null ? String(q.checkpoint) : null,
    FIELD,
    undefined,
    true,
    q.last != null ? String(q.last) : null,
  )
  return (res.body.data as Record<string, unknown>)[FIELD] as unknown[]
}

describe("appendOnly segmented storage (chunkSize) — parity with single-doc", () => {
  // 25 elements, ts 10..250, chunkSize 10 → chunks [10..100],[110..200],[210..250].
  const seq = seqOf(25)
  const queries: Array<{ checkpoint?: number; last?: number }> = [
    {}, // full
    { checkpoint: 0 },
    { checkpoint: 5 }, // before all
    { checkpoint: 100 }, // == last ts of chunk 0 (boundary)
    { checkpoint: 105 }, // in the gap between chunk 0 and chunk 1
    { checkpoint: 110 }, // == firstTs of chunk 1
    { checkpoint: 155 }, // inside chunk 1
    { checkpoint: 250 }, // == last element
    { checkpoint: 300 }, // after all
    { last: 0 },
    { last: 3 }, // within one chunk
    { last: 10 }, // == chunkSize
    { last: 15 }, // spanning chunks
    { last: 100 }, // > n
    { checkpoint: 100, last: 2 },
    { checkpoint: 5, last: 12 },
    { checkpoint: 110, last: 5 },
  ]

  it("returns identical pull responses across every checkpoint/last combination", async () => {
    const seg = new MemoryObjectStore(new Map())
    const single = new MemoryObjectStore(new Map())
    await runSeq(seg, "k", seq, { chunkSize: 10 })
    await runSeq(single, "k", seq, {})
    for (const q of queries) {
      expect(await pull(seg, "k", q), `query ${JSON.stringify(q)}`).toEqual(await pull(single, "k", q))
    }
  })

  it("returns a hash byte-identical to single-doc at the same (n, last)", async () => {
    const seg = new MemoryObjectStore(new Map())
    const single = new MemoryObjectStore(new Map())
    const segHash = await runSeq(seg, "k", seq, { chunkSize: 10 })
    const singleHash = await runSeq(single, "k", seq, {})
    expect(segHash).toBe(singleHash)
  })

  it("rolls over to a new chunk exactly at the chunkSize boundary", async () => {
    const store = new MemoryObjectStore(new Map())
    await runSeq(store, "k", seqOf(10), { chunkSize: 10 })
    expect(await store.listKeys(appendSegPrefix("k"))).toHaveLength(1)
    await appendItem(store, "k", { n: 11 }, FIELD, 110, { chunkSize: 10 })
    const keys = await store.listKeys(appendSegPrefix("k"))
    expect(keys).toHaveLength(2)
    expect(JSON.parse((await store.getString(keys[0]!))!)).toHaveLength(10)
    expect(JSON.parse((await store.getString(keys[1]!))!)).toHaveLength(1)
    expect(await pull(store, "k")).toHaveLength(11)
  })
})

describe("appendOnly segmented storage — lazy migration & stickiness", () => {
  it("lazily migrates a legacy single-doc into chunks on the first chunked append", async () => {
    const store = new MemoryObjectStore(new Map())
    await runSeq(store, "k", seqOf(25), {}) // legacy single-doc
    expect(await store.listKeys(appendSegPrefix("k"))).toHaveLength(0)
    await appendItem(store, "k", { n: 26 }, FIELD, 260, { chunkSize: 10 })
    expect(await store.listKeys(appendSegPrefix("k"))).toHaveLength(3) // ceil(26/10)
    const items = (await pull(store, "k")) as Array<{ data: { n: number } }>
    expect(items.map((e) => e.data.n)).toEqual(Array.from({ length: 26 }, (_, i) => i + 1))
  })

  it("migrates an exact chunkSize multiple by starting a fresh tail chunk", async () => {
    const store = new MemoryObjectStore(new Map())
    await runSeq(store, "k", seqOf(20), {}) // 20 = 2 × chunkSize
    await appendItem(store, "k", { n: 21 }, FIELD, 210, { chunkSize: 10 })
    const keys = await store.listKeys(appendSegPrefix("k"))
    expect(keys).toHaveLength(3) // two sealed (10+10) + one new (1)
    expect(JSON.parse((await store.getString(keys[2]!))!)).toHaveLength(1)
    expect(await pull(store, "k")).toHaveLength(21)
  })

  it("preserves non-array top-level fields through migration", async () => {
    const store = new MemoryObjectStore(new Map())
    await store.put("k", JSON.stringify({ v: 1, data: { items: [{ ts: 10, data: { n: 1 } }], meta: "keep" }, ts: 10, hash: "x" }))
    await appendItem(store, "k", { n: 2 }, FIELD, 20, { chunkSize: 10 })
    const res = await handleAppendOnlyPull("k", store, null, FIELD)
    const data = res.body.data as Record<string, unknown>
    expect(data["meta"]).toBe("keep")
    expect(data[FIELD]).toHaveLength(2)
  })

  it("stays chunked when chunkSize is later removed from config (no orphaned chunks)", async () => {
    const store = new MemoryObjectStore(new Map())
    await runSeq(store, "k", seqOf(15), { chunkSize: 10 }) // 2 chunks
    // Config drift: this append carries NO chunkSize. Must NOT overwrite the head
    // as a single-doc and orphan the chunks.
    const out = await appendItem(store, "k", { n: 16 }, FIELD, 160, {})
    expect("hash" in out).toBe(true)
    const head = JSON.parse((await store.getString("k"))!)
    expect(head.seg).toBe(true)
    expect(await pull(store, "k")).toHaveLength(16)
  })

  it("works on the filesystem backend (head file + chunk dir coexist)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "starfish-seg-"))
    try {
      const store = new FilesystemObjectStore({ baseDir: dir })
      await runSeq(store, "events", seqOf(15), { chunkSize: 10 })
      expect(await pull(store, "events")).toHaveLength(15)
      expect(await pull(store, "events", { checkpoint: 100 })).toHaveLength(5) // ts 110..150
      expect(await store.getString("events")).toBeTruthy() // head readable as a normal doc
      expect(await store.listKeys(appendSegPrefix("events"))).toHaveLength(2)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe("appendOnly maxItems cap", () => {
  it("accepts up to the cap and rejects the next (protocol level), without storing it", async () => {
    const store = new MemoryObjectStore(new Map())
    await appendItem(store, "k", { n: 1 }, FIELD, 10, { maxItems: 2 })
    await appendItem(store, "k", { n: 2 }, FIELD, 20, { maxItems: 2 }) // exactly at cap → ok
    const out = await appendItem(store, "k", { n: 3 }, FIELD, 30, { maxItems: 2 })
    expect(out).toEqual({ error: "append_limit_exceeded", limit: 2 })
    expect(JSON.parse((await store.getString("k"))!).data.items).toHaveLength(2)
  })

  it("enforces the cap with chunked storage too (combined knobs)", async () => {
    const store = new MemoryObjectStore(new Map())
    await runSeq(store, "k", seqOf(25), { chunkSize: 10, maxItems: 25 })
    const out = await appendItem(store, "k", { n: 26 }, FIELD, 260, { chunkSize: 10, maxItems: 25 })
    expect(out).toEqual({ error: "append_limit_exceeded", limit: 25 })
    expect(await pull(store, "k")).toHaveLength(25)
  })
})

describe("appendOnly maxItems cap — router 409", () => {
  function makeRouter(col: CollectionConfig) {
    const store = new MemoryObjectStore(new Map())
    const config: SyncConfig = { version: 1, collections: [col] }
    const opts: SyncRouterOptions = {
      store,
      config,
      roleResolver: async (): Promise<AuthResult> => ({ identity: "user-1", roles: ["admin"] }),
    }
    return createSyncRouter(opts)
  }
  const col: CollectionConfig = {
    name: "events",
    storagePath: "events",
    readRoles: ["admin"],
    writeRoles: ["admin"],
    encryption: "none",
    maxBodyBytes: 65536,
    allowedMimeTypes: ["application/json"],
    appendOnly: { type: "by_timestamp", maxItems: 1 },
  }
  const push = (app: ReturnType<typeof createSyncRouter>, item: unknown) =>
    app.request("/push/events", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ data: item }) })

  it("returns 409 { error: append_limit_exceeded, limit } past the cap", async () => {
    const app = makeRouter(col)
    expect((await push(app, { n: 1 })).status).toBe(200)
    const res = await push(app, { n: 2 })
    expect(res.status).toBe(409)
    expect(await res.json()).toEqual({ error: "append_limit_exceeded", limit: 1 })
  })
})

describe("chunked append-only — head.n does not drift across a crash (sealedN self-heal)", () => {
  it("recomputes the true count when the head was left one element behind", async () => {
    const store = new MemoryObjectStore()
    const key = "log"
    const opts: AppendOptions = { chunkSize: 3 }

    // Build: chunk1 = [10,20,30] (sealed), tail = [40]. → head.n=4, sealedN=3.
    await runSeq(store, key, seqOf(4), opts)
    let head = JSON.parse((await store.getString(key))!) as Record<string, unknown>
    expect(head.n).toBe(4)
    expect(head.sealedN).toBe(3)
    const tailKey = head.tailKey as string

    // Simulate a crash AFTER the chunk write but BEFORE the head write: the tail
    // chunk gains a 5th element (ts 50) on disk, but the head still says n=4 /
    // sealedN=3 (it was never updated). Old code read head.n and did n+1, so the
    // count drifted permanently; the sealedN re-derivation must self-heal.
    await store.put(
      tailKey,
      JSON.stringify([
        { ts: 40, data: { n: 4 } },
        { ts: 50, data: { n: 5 } },
      ]),
      { contentType: "application/json" },
    )
    // (head is still { n:4, sealedN:3, tailKey } — the stale post-crash state.)

    // Next append (ts 60). Authoritative count = sealedN(3) + tail([40,50]=2) + 1 = 6.
    const out = await appendItem(store, key, { n: 6 }, FIELD, 60, opts)
    expect("hash" in out).toBe(true)

    head = JSON.parse((await store.getString(key))!) as Record<string, unknown>
    expect(head.n).toBe(6) // NOT 5 — the drift was corrected
    expect(head.sealedN).toBe(3)

    // And the data is intact: a full pull returns all 6 elements in order.
    const all = await pull(store, key)
    expect(all.map((e) => (e as { ts: number }).ts)).toEqual([10, 20, 30, 40, 50, 60])
  })
})
