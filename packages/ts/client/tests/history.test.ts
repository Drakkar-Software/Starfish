import { describe, it, expect, vi, beforeEach } from "vitest"
import { SnapshotHistory } from "../src/history.js"

describe("SnapshotHistory", () => {
  it("take and list snapshots", () => {
    const history = new SnapshotHistory()
    history.take("save 1", { a: 1 })
    history.take("save 2", { b: 2 })

    const list = history.list()
    expect(list).toHaveLength(2)
    expect(list[0].label).toBe("save 1")
    expect(list[1].label).toBe("save 2")
    expect(list[0].timestamp).toBeLessThanOrEqual(Date.now())
  })

  it("restore returns parsed data", () => {
    const history = new SnapshotHistory()
    history.take("test", { key: "value", nested: { x: 1 } })

    const restored = history.restore(0)
    expect(restored).toEqual({ key: "value", nested: { x: 1 } })
  })

  it("restore returns undefined for invalid index", () => {
    const history = new SnapshotHistory()
    expect(history.restore(0)).toBeUndefined()
    expect(history.restore(-1)).toBeUndefined()
    expect(history.restore(999)).toBeUndefined()
  })

  it("restore returns undefined for corrupt snapshot data", () => {
    const storage: Record<string, string> = {}
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage[key] ?? null,
      setItem: (key: string, value: string) => { storage[key] = value },
    })

    // Load a snapshot with corrupt data directly into storage
    storage["test-corrupt"] = JSON.stringify([
      { timestamp: 1000, label: "bad", data: "not valid json{{{" },
    ])

    const history = new SnapshotHistory({ storageKey: "test-corrupt" })
    expect(history.restore(0)).toBeUndefined()
  })

  it("trims oldest snapshots when exceeding maxSnapshots", () => {
    const history = new SnapshotHistory({ maxSnapshots: 3 })
    history.take("a", { v: 1 })
    history.take("b", { v: 2 })
    history.take("c", { v: 3 })
    history.take("d", { v: 4 })

    const list = history.list()
    expect(list).toHaveLength(3)
    expect(list[0].label).toBe("b")
    expect(list[2].label).toBe("d")
  })

  it("clear removes all snapshots", () => {
    const history = new SnapshotHistory()
    history.take("a", { v: 1 })
    history.take("b", { v: 2 })
    history.clear()

    expect(history.list()).toHaveLength(0)
    expect(history.restore(0)).toBeUndefined()
  })

  describe("persistence", () => {
    let storage: Record<string, string>

    beforeEach(() => {
      storage = {}
      vi.stubGlobal("localStorage", {
        getItem: (key: string) => storage[key] ?? null,
        setItem: (key: string, value: string) => { storage[key] = value },
        removeItem: (key: string) => { delete storage[key] },
      })
    })

    it("persists snapshots on take", () => {
      const history = new SnapshotHistory({ storageKey: "test-history" })
      history.take("save", { data: true })

      const stored = JSON.parse(storage["test-history"])
      expect(stored).toHaveLength(1)
      expect(stored[0].label).toBe("save")
    })

    it("loads snapshots on construction", () => {
      storage["test-history"] = JSON.stringify([
        { timestamp: 1000, label: "old", data: '{"x":1}' },
      ])

      const history = new SnapshotHistory({ storageKey: "test-history" })
      expect(history.list()).toHaveLength(1)
      expect(history.restore(0)).toEqual({ x: 1 })
    })

    it("persists clear", () => {
      const history = new SnapshotHistory({ storageKey: "test-history" })
      history.take("a", { v: 1 })
      history.clear()

      const stored = JSON.parse(storage["test-history"])
      expect(stored).toHaveLength(0)
    })

    it("handles corrupted storage gracefully", () => {
      storage["test-history"] = "not valid json"
      const history = new SnapshotHistory({ storageKey: "test-history" })
      expect(history.list()).toHaveLength(0)
    })

    it("handles localStorage.setItem failure gracefully", () => {
      vi.stubGlobal("localStorage", {
        getItem: () => null,
        setItem: () => { throw new Error("QuotaExceededError") },
      })

      const history = new SnapshotHistory({ storageKey: "test-history" })
      // Should not throw
      expect(() => history.take("save", { data: true })).not.toThrow()
      expect(history.list()).toHaveLength(1)
    })
  })
})
