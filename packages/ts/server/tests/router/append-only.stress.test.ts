// Stress tests characterizing append-only parse/serialize cost as a log grows.
//
// The whole feature stores every element in ONE JSON blob per document, so every
// append rewrites the blob and every pull parses it in full. These tests measure
// that cost at increasing document sizes — they don't assert tight timings (those
// flake across hardware); they print numbers and assert only generous ceilings so
// a regression that turns linear into something pathological still trips, and a
// hang can't run forever.
//
// Opt-in only — gated behind STARFISH_STRESS so the default `pnpm test` stays fast:
//   STARFISH_STRESS=1 pnpm exec vitest run tests/router/append-only.stress.test.ts --reporter=verbose
//
// Layer: calls the protocol/router functions directly (no HTTP) to isolate the
// document-parse cost from request/response overhead.

import { describe, it, expect } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { appendItem, appendChunkKey, appendSegPrefix } from "../../src/protocol/push.js"
import { handleAppendOnlyPull } from "../../src/router/helpers.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"

// appendItem computes a hash via the platform crypto, so the platform must be
// configured even though the seed documents carry a placeholder hash.
configurePlatform({
  crypto: webcrypto as unknown as Crypto,
  base64: {
    encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
    decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
  },
})

const FIELD = "items"
const SIZES = [1_000, 10_000, 50_000, 100_000]
const PAYLOAD_SMALL = 8 // bytes of filler per element
const PAYLOAD_LARGE = 1024 // ~1 KB per element
const TIMEOUT = 120_000 // vitest default is 5s; these need much longer

/**
 * Build and store a document already holding `n` elements, each `{ts, data}`
 * with `ts` = 1..n (strictly increasing, so the pull-side binary search is valid)
 * and `data` carrying `payloadBytes` of filler. Append/pull never verify the
 * stored `hash`, so a placeholder is fine — no need to recompute it.
 */
async function seedStore(key: string, n: number, payloadBytes: number): Promise<MemoryObjectStore> {
  const store = new MemoryObjectStore(new Map())
  const filler = "x".repeat(payloadBytes)
  const items = new Array<{ ts: number; data: { v: string } }>(n)
  for (let i = 0; i < n; i++) items[i] = { ts: i + 1, data: { v: filler } }
  const doc = { v: 1, data: { [FIELD]: items }, ts: n, hash: "" }
  await store.put(key, JSON.stringify(doc), { contentType: "application/json" })
  return store
}

/**
 * Pre-seed a SEGMENTED document holding `n` elements directly (no sequential
 * append — that would be O(n·chunkSize) to build). Writes ceil(n/chunkSize) chunk
 * objects (each keyed by its first element's `ts`) plus the head doc, mirroring
 * what `appendItem({ chunkSize })` would produce. The tail chunk holds the
 * remainder (`n % chunkSize`), so a subsequent append exercises the realistic
 * read-modify-write of a partial tail.
 */
async function seedChunked(key: string, n: number, payloadBytes: number, chunkSize: number): Promise<MemoryObjectStore> {
  const store = new MemoryObjectStore(new Map())
  const filler = "x".repeat(payloadBytes)
  let tailKey = ""
  for (let start = 0; start < n; start += chunkSize) {
    const end = Math.min(start + chunkSize, n)
    const arr = new Array<{ ts: number; data: { v: string } }>(end - start)
    for (let i = start; i < end; i++) arr[i - start] = { ts: i + 1, data: { v: filler } }
    tailKey = appendChunkKey(key, start + 1) // firstTs of this chunk = start + 1
    await store.put(tailKey, JSON.stringify(arr), { contentType: "application/json" })
  }
  const head = { v: 1, seg: true, data: {}, n, ts: n, hash: "", chunkSize, tailKey }
  await store.put(key, JSON.stringify(head), { contentType: "application/json" })
  return store
}

function pulledItems(res: { body: Record<string, unknown> }): unknown[] {
  const data = res.body.data as Record<string, unknown>
  return data[FIELD] as unknown[]
}

const fmt = (n: number) => n.toLocaleString("en-US")

// Distinct documentKey per case/N — the module-level write chain serialises by
// key, so sharing a key across tests would queue unrelated work into the timing.
describe.skipIf(!process.env.STARFISH_STRESS)("append-only stress: parse cost vs document size", () => {
  it("append to a pre-seeded doc — cost grows ~linearly with current size (=> O(n^2) to build)", async () => {
    for (const n of SIZES) {
      const key = `stress/append/${n}`
      const store = await seedStore(key, n, PAYLOAD_SMALL)
      const t0 = performance.now()
      const out = await appendItem(store, key, { v: "appended" }, FIELD, n + 1)
      const dt = performance.now() - t0
      console.log(`[append]            N=${fmt(n).padStart(9)} -> ${dt.toFixed(2)} ms`)
      expect(out).toMatchObject({ timestamp: n + 1 })
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("full pull (checkpoint=0) — parses the whole blob, ~linear with size", async () => {
    for (const n of SIZES) {
      const key = `stress/fullpull/${n}`
      const store = await seedStore(key, n, PAYLOAD_SMALL)
      const t0 = performance.now()
      const res = await handleAppendOnlyPull(key, store, "0", FIELD)
      const dt = performance.now() - t0
      const items = pulledItems(res)
      console.log(`[full-pull]         N=${fmt(n).padStart(9)} -> ${dt.toFixed(2)} ms (returned ${fmt(items.length)})`)
      expect(items.length).toBe(n)
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("checkpoint-at-tail pull (~10 survivors) — still O(n): the whole blob is parsed first", async () => {
    // The checkpoint only trims what is RETURNED. The server still reads + parses
    // the entire blob before the binary search, so this is not cheaper than a full
    // pull in parse cost. (In Python the gap is wider: handle_append_only_pull
    // builds a full element_ts list — an extra O(n) pass — before bisect.)
    for (const n of SIZES) {
      const key = `stress/checkpoint/${n}`
      const store = await seedStore(key, n, PAYLOAD_SMALL)
      const checkpoint = String(n - 10) // survivors: ts in (n-10 .. n] => 10 elements
      const t0 = performance.now()
      const res = await handleAppendOnlyPull(key, store, checkpoint, FIELD)
      const dt = performance.now() - t0
      const items = pulledItems(res)
      console.log(`[checkpoint-tail]   N=${fmt(n).padStart(9)} -> ${dt.toFixed(2)} ms (returned ${fmt(items.length)})`)
      expect(items.length).toBe(10)
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("sequential build is quadratic — per-item append time climbs as the log grows", async () => {
    // Real-world shape: an app that appends forever without ever resetting the doc.
    // Kept to <=10k items because total work is O(n^2).
    for (const n of [1_000, 5_000, 10_000]) {
      const key = `stress/seqbuild/${n}`
      const store = new MemoryObjectStore(new Map())
      const t0 = performance.now()
      for (let i = 0; i < n; i++) await appendItem(store, key, { i }, FIELD, i + 1)
      const dt = performance.now() - t0
      console.log(`[seq-build]         N=${fmt(n).padStart(9)} -> total ${dt.toFixed(2)} ms, ${((dt / n) * 1000).toFixed(2)} us/item`)
      const raw = await store.getString(key)
      expect(JSON.parse(raw!).data[FIELD].length).toBe(n)
      expect(dt).toBeLessThan(60_000)
    }
  }, TIMEOUT)

  it("chunked sequential build is ~linear — per-item append time stays flat as the log grows", async () => {
    // Contrast with `sequential build is quadratic` above: with chunkSize an append
    // touches only the open tail chunk, so per-item time stays bounded (no O(n²)).
    const chunkSize = 1_000
    for (const n of [1_000, 5_000, 10_000]) {
      const key = `stress/chunked-build/${n}`
      const store = new MemoryObjectStore(new Map())
      const t0 = performance.now()
      for (let i = 0; i < n; i++) await appendItem(store, key, { i }, FIELD, i + 1, { chunkSize })
      const dt = performance.now() - t0
      console.log(`[chunked-build]     N=${fmt(n).padStart(9)} -> total ${dt.toFixed(2)} ms, ${((dt / n) * 1000).toFixed(2)} us/item`)
      expect(dt).toBeLessThan(60_000)
    }
  }, TIMEOUT)

  it("large payload @ 100k (~100 MB blob) — bytes drive cost, not just element count", async () => {
    const key = "stress/large/100k"
    const store = await seedStore(key, 100_000, PAYLOAD_LARGE)

    const tA = performance.now()
    const out = await appendItem(store, key, { v: "x".repeat(PAYLOAD_LARGE) }, FIELD, 100_001)
    const dtAppend = performance.now() - tA

    const tP = performance.now()
    const res = await handleAppendOnlyPull(key, store, "0", FIELD)
    const dtPull = performance.now() - tP

    console.log(`[large-100k ~100MB] append ${dtAppend.toFixed(2)} ms, full-pull ${dtPull.toFixed(2)} ms`)
    expect(out).toMatchObject({ timestamp: 100_001 })
    expect(pulledItems(res).length).toBe(100_001)
    expect(dtPull).toBeLessThan(60_000)
  }, TIMEOUT)
})

// Comprehensive characterization of the SEGMENTED (`chunkSize`) layout across sizes.
// The point: with chunking, append and tail-oriented pulls are bounded by chunkSize
// and stay ~flat as the total log grows, where the single-doc layout is O(n). Docs
// are pre-seeded directly (building 1M elements by sequential append would be slow).
describe.skipIf(!process.env.STARFISH_STRESS)("append-only chunked storage perf vs document size", () => {
  const CHUNK = 10_000
  const CHUNK_SIZES = [10_000, 100_000, 1_000_000] // total element counts
  const w = (n: number) => fmt(n).padStart(11)

  it("append cost is ~flat vs N (bounded by chunkSize, not total size)", async () => {
    for (const n of CHUNK_SIZES) {
      const key = `cperf/append/${n}`
      const store = await seedChunked(key, n, PAYLOAD_SMALL, CHUNK)
      const t0 = performance.now()
      const out = await appendItem(store, key, { v: "appended" }, FIELD, n + 1, { chunkSize: CHUNK })
      const dt = performance.now() - t0
      console.log(`[chunk append]      N=${w(n)} cs=${fmt(CHUNK)} -> ${dt.toFixed(2)} ms`)
      expect(out).toMatchObject({ timestamp: n + 1 })
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("checkpoint-tail pull is ~flat vs N (reads only the boundary chunk)", async () => {
    for (const n of CHUNK_SIZES) {
      const key = `cperf/cp/${n}`
      const store = await seedChunked(key, n, PAYLOAD_SMALL, CHUNK)
      const totalChunks = (await store.listKeys(appendSegPrefix(key))).length
      const t0 = performance.now()
      const res = await handleAppendOnlyPull(key, store, String(n - 10), FIELD)
      const dt = performance.now() - t0
      const items = pulledItems(res)
      console.log(`[chunk cp-tail]     N=${w(n)} (${fmt(totalChunks)} chunks) -> ${dt.toFixed(2)} ms (returned ${items.length})`)
      expect(items.length).toBe(10)
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("last=100 pull is ~flat vs N (reads only the final chunk)", async () => {
    for (const n of CHUNK_SIZES) {
      const key = `cperf/last/${n}`
      const store = await seedChunked(key, n, PAYLOAD_SMALL, CHUNK)
      const t0 = performance.now()
      const res = await handleAppendOnlyPull(key, store, null, FIELD, undefined, true, "100")
      const dt = performance.now() - t0
      console.log(`[chunk last=100]    N=${w(n)} -> ${dt.toFixed(2)} ms (returned ${pulledItems(res).length})`)
      expect(pulledItems(res).length).toBe(100)
      expect(dt).toBeLessThan(10_000)
    }
  }, TIMEOUT)

  it("full pull grows with N (reads every chunk — returns everything)", async () => {
    for (const n of CHUNK_SIZES) {
      const key = `cperf/full/${n}`
      const store = await seedChunked(key, n, PAYLOAD_SMALL, CHUNK)
      const t0 = performance.now()
      const res = await handleAppendOnlyPull(key, store, "0", FIELD)
      const dt = performance.now() - t0
      console.log(`[chunk full-pull]   N=${w(n)} -> ${dt.toFixed(2)} ms (returned ${fmt(pulledItems(res).length)})`)
      expect(pulledItems(res).length).toBe(n)
      expect(dt).toBeLessThan(60_000)
    }
  }, TIMEOUT)

  it("chunkSize sweep @ N=100k — append & checkpoint cost scale with chunkSize, not N", async () => {
    const N = 100_000
    for (const cs of [1_000, 10_000, 50_000]) {
      const key = `cperf/sweep/${cs}`
      const store = await seedChunked(key, N, PAYLOAD_SMALL, cs)
      const tA = performance.now()
      await appendItem(store, key, { v: "appended" }, FIELD, N + 1, { chunkSize: cs })
      const dtA = performance.now() - tA
      const tP = performance.now()
      await handleAppendOnlyPull(key, store, String(N - 10), FIELD)
      const dtP = performance.now() - tP
      console.log(`[chunk sweep]       N=${fmt(N)} cs=${fmt(cs).padStart(7)} -> append ${dtA.toFixed(2)} ms, cp-tail ${dtP.toFixed(2)} ms`)
    }
  }, TIMEOUT)

  it("side-by-side @ N=100k — chunked vs single-doc (append + checkpoint-tail)", async () => {
    const N = 100_000
    const single = await seedStore("cperf/cmp-single", N, PAYLOAD_SMALL)
    let t = performance.now()
    await appendItem(single, "cperf/cmp-single", { v: "x" }, FIELD, N + 1)
    const sAppend = performance.now() - t
    t = performance.now()
    await handleAppendOnlyPull("cperf/cmp-single", single, String(N - 10), FIELD)
    const sPull = performance.now() - t

    const chunked = await seedChunked("cperf/cmp-chunked", N, PAYLOAD_SMALL, CHUNK)
    t = performance.now()
    await appendItem(chunked, "cperf/cmp-chunked", { v: "x" }, FIELD, N + 1, { chunkSize: CHUNK })
    const cAppend = performance.now() - t
    t = performance.now()
    await handleAppendOnlyPull("cperf/cmp-chunked", chunked, String(N - 10), FIELD)
    const cPull = performance.now() - t

    console.log(`[cmp @100k] append:  single ${sAppend.toFixed(2)} ms  vs  chunked ${cAppend.toFixed(2)} ms`)
    console.log(`[cmp @100k] cp-tail: single ${sPull.toFixed(2)} ms  vs  chunked ${cPull.toFixed(2)} ms`)
  }, TIMEOUT)
})
