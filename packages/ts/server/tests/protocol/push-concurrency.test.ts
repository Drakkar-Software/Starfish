/**
 * Concurrent push serialization — per-key promise queue prevents TOCTOU.
 *
 * Node.js is single-threaded, but `await` lets other microtasks run between
 * the getString read and the put write. Two concurrent pushes with the same
 * baseHash both read before either writes, both pass the hash check, both
 * succeed — the second write silently overwrites the first.
 *
 * Fix: a per-key promise chain serializes pushes so the second push only
 * starts after the first's put has completed.
 */
import { describe, it, expect } from "vitest"
import { push } from "../../src/protocol/push.js"
import { MemoryObjectStore } from "../../src/storage/memory.js"
import type { ObjectStore } from "../../src/storage/base.js"

/** Wraps a MemoryObjectStore and yields after getString to expose the TOCTOU window. */
function makeYieldingStore(): ObjectStore {
  const data = new Map<string, string>()
  const inner = new MemoryObjectStore(data)
  return {
    getString: async (key: string) => {
      const result = await inner.getString(key)
      // Yield to the microtask queue — simulates real I/O latency
      await new Promise<void>((resolve) => setImmediate(resolve))
      return result
    },
    put: inner.put.bind(inner),
    listKeys: inner.listKeys.bind(inner),
    delete: inner.delete.bind(inner),
    deleteMany: inner.deleteMany.bind(inner),
  }
}

describe("concurrent push serialization", () => {
  it("two concurrent pushes with same baseHash → 1 success + 1 conflict", async () => {
    const store = makeYieldingStore()

    // Establish an initial document and capture its hash
    const r0 = await push(store, "col/doc1", { a: 0 }, null)
    expect("hash" in r0).toBe(true)
    const baseHash = (r0 as { hash: string }).hash

    // Fire both pushes concurrently — they both start before either write completes
    const [rA, rB] = await Promise.all([
      push(store, "col/doc1", { a: 1 }, baseHash),
      push(store, "col/doc1", { a: 2 }, baseHash),
    ])

    const results = [rA, rB]
    const successes = results.filter((r) => "hash" in r)
    const conflicts = results.filter((r) => "error" in r)

    // fix not present → both succeed (TOCTOU) → FAILS
    expect(successes).toHaveLength(1)
    expect(conflicts).toHaveLength(1)
  })

  it("sequential pushes still work correctly after serialization is added", async () => {
    const store = makeYieldingStore()

    const r1 = await push(store, "col/doc1", { a: 1 }, null)
    expect("hash" in r1).toBe(true)

    const r2 = await push(store, "col/doc1", { a: 2 }, (r1 as { hash: string }).hash)
    expect("hash" in r2).toBe(true)

    const r3 = await push(store, "col/doc1", { a: 3 }, "wrong-hash")
    expect("error" in r3).toBe(true)
  })

  it("concurrent pushes to different keys do not block each other", async () => {
    const store = makeYieldingStore()

    // Two pushes to *different* keys must both succeed concurrently
    const [rA, rB] = await Promise.all([
      push(store, "col/docA", { x: 1 }, null),
      push(store, "col/docB", { y: 2 }, null),
    ])

    expect("hash" in rA).toBe(true)
    expect("hash" in rB).toBe(true)
  })
})
