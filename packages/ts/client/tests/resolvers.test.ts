import { describe, it, expect } from "vitest"
import {
  createUnionMerge,
  createSoftDeleteResolver,
  timestampWinner,
  pruneTombstones,
} from "../src/resolvers.js"

describe("createUnionMerge", () => {
  const merge = createUnionMerge()

  it("unions arrays by id", () => {
    const local = {
      timestamp: "2026-04-07T10:00:00Z",
      items: [
        { id: "a", name: "Alice" },
        { id: "b", name: "Bob" },
      ],
    }
    const remote = {
      timestamp: "2026-04-07T09:00:00Z",
      items: [
        { id: "b", name: "Bobby" },
        { id: "c", name: "Charlie" },
      ],
    }

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string; name: string }>

    expect(items).toHaveLength(3)
    expect(items.find((i) => i.id === "a")?.name).toBe("Alice")
    expect(items.find((i) => i.id === "c")?.name).toBe("Charlie")
  })

  it("uses updatedAt to pick the newer item", () => {
    const local = {
      timestamp: "2026-04-07T10:00:00Z",
      guests: [
        { id: "1", name: "Old Name", updatedAt: "2026-04-06T10:00:00Z" },
      ],
    }
    const remote = {
      timestamp: "2026-04-07T09:00:00Z",
      guests: [
        { id: "1", name: "New Name", updatedAt: "2026-04-07T09:30:00Z" },
      ],
    }

    const result = merge(local, remote)
    const guests = result.guests as Array<{ id: string; name: string }>

    expect(guests[0].name).toBe("New Name")
  })

  it("falls back to local when neither has updatedAt", () => {
    const local = {
      timestamp: "2026-04-07T10:00:00Z",
      items: [{ id: "1", name: "Local" }],
    }
    const remote = {
      timestamp: "2026-04-07T09:00:00Z",
      items: [{ id: "1", name: "Remote" }],
    }

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string; name: string }>
    expect(items[0].name).toBe("Local")
  })

  it("uses document timestamp for scalar values", () => {
    const local = { timestamp: "2026-04-07T08:00:00Z", title: "Old" }
    const remote = { timestamp: "2026-04-07T10:00:00Z", title: "New" }

    const result = merge(local, remote)
    expect(result.title).toBe("New")
  })

  it("preserves keys only present on one side", () => {
    const local = { timestamp: "2026-04-07T10:00:00Z", a: 1 }
    const remote = { timestamp: "2026-04-07T09:00:00Z", b: 2 }

    const result = merge(local, remote)
    expect(result.a).toBe(1)
    expect(result.b).toBe(2)
  })

  it("handles numeric timestamps correctly", () => {
    const merge = createUnionMerge({
      timestampKey: "ts",
      documentTimestampKey: "docTs",
    })

    const local = {
      docTs: 1000,
      items: [{ id: "1", val: "local", ts: 999 }],
    }
    const remote = {
      docTs: 900,
      items: [{ id: "1", val: "remote", ts: 1000 }],
    }

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string; val: string }>
    // Remote item has ts=1000 > local ts=999, so remote wins per-item
    expect(items[0].val).toBe("remote")
    // But local docTs=1000 > remote docTs=900, so local wins for scalars
    expect(result.docTs).toBe(1000)
  })

  it("supports custom keys", () => {
    const merge = createUnionMerge({
      idKey: "uid",
      timestampKey: "modifiedAt",
      documentTimestampKey: "ts",
    })

    const local = {
      ts: "2",
      items: [{ uid: "x", val: "local", modifiedAt: "2" }],
    }
    const remote = {
      ts: "1",
      items: [{ uid: "x", val: "remote", modifiedAt: "1" }],
    }

    const result = merge(local, remote)
    const items = result.items as Array<{ uid: string; val: string }>
    expect(items[0].val).toBe("local")
  })

  // ── advanced micro-edges ──────────────────────────────────────────────────

  // B1 — equal updatedAt tie: local wins (compareTimestamps uses >=).
  // This is the load-bearing contract for the "cache seed holds a locally-edited item
  // at the same timestamp as the server" scenario.
  it("B1: equal updatedAt tie — local item wins (compareTimestamps uses >=)", () => {
    const local = { items: [{ id: "x", updatedAt: 5, val: "local" }] }
    const remote = { items: [{ id: "x", updatedAt: 5, val: "remote" }] }

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string; val: string }>
    // compareTimestamps(5, 5) = 5 >= 5 = true → local wins on tie
    expect(items[0].val).toBe("local")
  })

  // B2 — items missing idKey are kept from both sides without deduplication.
  // Each keyless item is stored under a unique Symbol(), so they are never matched
  // or overwritten — every keyless item from both local and remote survives.
  it("B2: items missing idKey are kept from both sides, never deduped", () => {
    const local = { items: [{ x: 1 }, { x: 2 }] }   // no 'id' field
    const remote = { items: [{ x: 3 }] }              // no 'id' field

    const result = merge(local, remote)
    // All 3 items survive — keyless items are never matched/merged
    expect((result.items as unknown[]).length).toBe(3)
  })

  // B3 — empty array on one side: union produces the other side's items.
  // The zero-element boundary ([], not just "shorter") was never explicitly tested.
  it("B3: empty local array + remote items → remote items kept; empty remote + local → local kept", () => {
    const r1 = merge({ items: [] }, { items: [{ id: "a" }] })
    expect((r1.items as Array<{ id: string }>).map((i) => i.id)).toEqual(["a"])

    const r2 = merge({ items: [{ id: "b" }] }, { items: [] })
    expect((r2.items as Array<{ id: string }>).map((i) => i.id)).toEqual(["b"])
  })

  // B4 — array on one side, scalar on the other for the same key.
  // The array check (Array.isArray(lv) && Array.isArray(rv)) is false, so the
  // resolver falls through to the document-timestamp scalar branch — meaning an
  // array field can be silently replaced by a scalar. FLAG: surprising behaviour.
  it("B4: array-vs-scalar type mismatch — scalar (doc-timestamp) branch wins (FLAG: surprising)", () => {
    // remote is newer (timestamp 2 > 1) → remote wins the scalar branch
    const local = { items: [{ id: "a" }], timestamp: 1 }
    const remote = { items: "not-an-array", timestamp: 2 }

    const result = merge(local, remote)
    // Remote doc is newer → result.items = "not-an-array" (array replaced by scalar)
    expect(result.items).toBe("not-an-array")
  })

  // B5 — nested non-array object is replaced wholesale, NOT deep-merged.
  // createUnionMerge uses the doc-timestamp scalar branch for plain objects, so
  // the newer document's version of the nested object wins in full. This differs
  // from deepMerge which recurses into nested objects. FLAG: differs from deepMerge.
  it("B5: nested plain object replaced wholesale by newer doc — not recursively merged (FLAG: differs from deepMerge)", () => {
    const local = { meta: { a: 1, keep: true }, timestamp: 2 }  // local is newer
    const remote = { meta: { b: 2 }, timestamp: 1 }

    const result = merge(local, remote)
    // Local timestamp (2) > remote (1) → local meta wins wholesale
    expect(result.meta).toEqual({ a: 1, keep: true })
    // 'b' from remote meta is NOT present — no deep merge of nested objects
    expect((result.meta as Record<string, unknown>).b).toBeUndefined()
  })

  // B6 — mixed numeric vs string per-item updatedAt falls to lexical comparison.
  // compareTimestamps() only takes the numeric branch when BOTH sides are numbers.
  // When one is a number and the other an ISO string, both are coerced via String()
  // and compared lexicographically — "1000" < "2026-01-01" lexically → remote wins,
  // even though epoch 1000 ms is older than 2026. FLAG: latent footgun class.
  it("B6: mixed numeric/string updatedAt falls to lexical compare — remote ISO string beats local number (FLAG: footgun)", () => {
    const local = { items: [{ id: "x", updatedAt: 1000, val: "local" }] }  // number
    const remote = { items: [{ id: "x", updatedAt: "2026-01-01", val: "remote" }] }  // ISO string

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string; val: string }>
    // String("1000") >= String("2026-01-01") → "1000" >= "2026-01-01" → false (lexical)
    // → remote wins despite being a string timestamp not a numeric epoch
    expect(items[0].val).toBe("remote")
  })
})

describe("createSoftDeleteResolver", () => {
  const merge = createSoftDeleteResolver()

  it("filters out alive items when a newer tombstone exists on the other side", () => {
    const local = {
      timestamp: "2026-04-07T10:00:00Z",
      items: [
        { id: "1", name: "Alice", updatedAt: "2026-04-06T10:00:00Z" },
        { id: "2", name: "Bob", updatedAt: "2026-04-06T10:00:00Z" },
      ],
    }
    const remote = {
      timestamp: "2026-04-07T09:00:00Z",
      items: [
        // Tombstone: deleted AFTER Alice's updatedAt, with a newer updatedAt so union merge keeps it
        { id: "1", name: "Alice", updatedAt: "2026-04-07T08:00:00Z", _deletedAt: 1712500000000 },
      ],
    }

    const result = merge(local, remote)
    const items = result.items as Array<Record<string, unknown>>

    // Bob is preserved (no tombstone)
    expect(items.find((i) => i.id === "2")).toBeDefined()
    // The tombstone (with _deletedAt) should be in the result
    const tombstone = items.find((i) => i.id === "1" && "_deletedAt" in i)
    expect(tombstone).toBeDefined()
    // There should be no alive Alice (without _deletedAt)
    const aliveAlice = items.filter((i) => i.id === "1" && !("_deletedAt" in i))
    expect(aliveAlice).toHaveLength(0)
  })

  it("keeps items without tombstones", () => {
    const local = {
      timestamp: "2026-04-07T10:00:00Z",
      items: [{ id: "1", name: "Alice", updatedAt: "2026-04-07T10:00:00Z" }],
    }
    const remote = {
      timestamp: "2026-04-07T09:00:00Z",
      items: [{ id: "2", name: "Bob", updatedAt: "2026-04-07T09:00:00Z" }],
    }

    const result = merge(local, remote)
    const items = result.items as Array<{ id: string }>
    expect(items).toHaveLength(2)
  })
})

describe("timestampWinner", () => {
  const resolve = timestampWinner()

  it("picks the document with the newer timestamp", () => {
    const local = { timestamp: "2026-04-07T08:00:00Z", data: "local" }
    const remote = { timestamp: "2026-04-07T10:00:00Z", data: "remote" }

    expect(resolve(local, remote)).toBe(remote)
  })

  it("picks local when timestamps are equal", () => {
    const local = { timestamp: "2026-04-07T10:00:00Z", data: "local" }
    const remote = { timestamp: "2026-04-07T10:00:00Z", data: "remote" }

    expect(resolve(local, remote)).toBe(local)
  })
})

describe("pruneTombstones", () => {
  it("keeps non-deleted items", () => {
    const items = [
      { id: "1", name: "Alice" },
      { id: "2", name: "Bob" },
    ]
    expect(pruneTombstones(items)).toEqual(items)
  })

  it("removes expired tombstones", () => {
    const items = [
      { id: "1", name: "Alice" },
      { id: "2", name: "Bob", _deletedAt: Date.now() - 60 * 24 * 60 * 60 * 1000 }, // 60 days ago
    ]
    const result = pruneTombstones(items)
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe("1")
  })

  it("keeps recent tombstones", () => {
    const items = [
      { id: "1", _deletedAt: Date.now() - 1000 }, // 1 second ago
    ]
    expect(pruneTombstones(items)).toHaveLength(1)
  })

  it("supports custom TTL", () => {
    const items = [
      { id: "1", _deletedAt: Date.now() - 5000 }, // 5 seconds ago
    ]
    expect(pruneTombstones(items, 3000)).toHaveLength(0) // 3s TTL
    expect(pruneTombstones(items, 10000)).toHaveLength(1) // 10s TTL
  })

  it("supports custom deletedAt key", () => {
    const items = [
      { id: "1", removedAt: Date.now() - 60 * 24 * 60 * 60 * 1000 },
    ]
    expect(pruneTombstones(items, undefined, "removedAt")).toHaveLength(0)
  })

  it("handles string ISO-8601 timestamps for deletedAt", () => {
    const recent = new Date(Date.now() - 1000).toISOString()
    const expired = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString()
    const items = [
      { id: "1", _deletedAt: recent },
      { id: "2", _deletedAt: expired },
    ]
    const result = pruneTombstones(items)
    expect(result).toHaveLength(1)
    expect(result[0].id).toBe("1")
  })
})
