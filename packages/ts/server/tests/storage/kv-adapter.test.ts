import { describe, it, expect } from "vitest"
import { createInMemoryKVAdapter } from "../../src/storage/kv-adapter.js"
import { createK2VAdapter, type K2VTransport, type K2VReadResult } from "../../src/storage/k2v-adapter.js"

describe("createInMemoryKVAdapter — increment", () => {
  it("counts up within the window and restarts after expiry", async () => {
    let clock = 1_000
    const kv = createInMemoryKVAdapter({ now: () => clock })
    expect(await kv.increment("k", 60_000)).toBe(1)
    expect(await kv.increment("k", 60_000)).toBe(2)
    clock += 60_001 // window elapsed
    expect(await kv.increment("k", 60_000)).toBe(1) // restarts
  })

  it("isolates counters per key", async () => {
    const kv = createInMemoryKVAdapter()
    expect(await kv.increment("a", 60_000)).toBe(1)
    expect(await kv.increment("a", 60_000)).toBe(2)
    expect(await kv.increment("b", 60_000)).toBe(1)
  })

  it("bounds the key count to maxKeys, evicting the oldest (no unbounded growth)", async () => {
    // A flood of distinct keys (e.g. spoofed X-Forwarded-For) must not grow memory
    // without bound. Mirrors the Python twin.
    const kv = createInMemoryKVAdapter({ maxKeys: 8 })
    for (let i = 0; i < 200; i++) await kv.increment(`k${i}`, 60_000)
    // No public size accessor; assert behaviorally: an old key was evicted (restarts at 1),
    // while a very recent key retains its count.
    expect(await kv.increment("k0", 60_000)).toBe(1) // k0 long evicted
    expect(await kv.increment("k199", 60_000)).toBe(2) // k199 still live
  })
})

describe("createInMemoryKVAdapter — recordIfAbsent", () => {
  it("records once, rejects within window, accepts after expiry", async () => {
    let clock = 1_000
    const kv = createInMemoryKVAdapter({ now: () => clock })
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(true)
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(false)
    clock += 60_001
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(true)
  })

  it("enforces a fail-closed per-group cap without evicting live entries", async () => {
    const kv = createInMemoryKVAdapter()
    const group = { key: "A", limit: 2 }
    expect(await kv.recordIfAbsent("a1", 60_000, group)).toBe(true)
    expect(await kv.recordIfAbsent("a2", 60_000, group)).toBe(true)
    expect(await kv.recordIfAbsent("a3", 60_000, group)).toBe(false) // at cap
    // A different group is unaffected.
    expect(await kv.recordIfAbsent("b1", 60_000, { key: "B", limit: 2 })).toBe(true)
  })
})

// --- K2V adapter over a mock transport ---

/** Minimal in-test K2V mock: stores siblings per (pk, sk); read returns all of them. */
function mockTransport(): K2VTransport & { siblings: Map<string, string[]> } {
  const siblings = new Map<string, string[]>()
  let token = 0
  return {
    siblings,
    async read(pk, sk): Promise<K2VReadResult> {
      const vals = siblings.get(`${pk}/${sk}`) ?? []
      return { values: [...vals], causality: vals.length ? `t${token}` : null }
    },
    async insert(pk, sk, value, causality) {
      const key = `${pk}/${sk}`
      if (causality) {
        // Superseding write replaces all current siblings.
        siblings.set(key, [value])
      } else {
        // Concurrent write (no token) appends a sibling.
        siblings.set(key, [...(siblings.get(key) ?? []), value])
      }
      token += 1
    },
  }
}

describe("createK2VAdapter", () => {
  it("increment counts up across calls (superseding writes merge)", async () => {
    let clock = 1_000
    const kv = createK2VAdapter({ transport: mockTransport(), now: () => clock })
    expect(await kv.increment("k", 60_000)).toBe(1)
    expect(await kv.increment("k", 60_000)).toBe(2)
    expect(await kv.increment("k", 60_000)).toBe(3)
    clock += 60_001
    expect(await kv.increment("k", 60_000)).toBe(1) // expired siblings ignored → restart
  })

  it("sums concurrent siblings (overcount = fail-closed, never undercount)", async () => {
    const t = mockTransport()
    const kv = createK2VAdapter({ transport: t, now: () => 1_000 })
    // Simulate two concurrent increments that both read causality=null (absent) and
    // both write without superseding → two sibling "1"s.
    t.siblings.set("starfish-kv/k", [
      JSON.stringify({ exp: 61_000, n: 1 }),
      JSON.stringify({ exp: 61_000, n: 1 }),
    ])
    // Next increment sums the siblings (1 + 1) + 1 = 3 (stricter than the "true" 3rd).
    expect(await kv.increment("k", 60_000)).toBe(3)
  })

  it("recordIfAbsent rejects a live flag and accepts after expiry", async () => {
    let clock = 1_000
    const kv = createK2VAdapter({ transport: mockTransport(), now: () => clock })
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(true)
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(false)
    clock += 60_001
    expect(await kv.recordIfAbsent("n", 60_000)).toBe(true)
  })
})
