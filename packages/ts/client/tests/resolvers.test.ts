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
})
