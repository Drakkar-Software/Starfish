import { describe, it, expect, vi } from "vitest"
import { createMultiStoreSync } from "../src/multi-store.js"
import type { BackupDocument } from "../src/multi-store.js"

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeSlice<T>(initial: T) {
  let current = initial
  return {
    slice: {
      serialize: () => current,
      restore: (data: T) => { current = data },
    },
    get: () => current,
    set: (val: T) => { current = val },
  }
}

// ── serialize ─────────────────────────────────────────────────────────────────

describe("createMultiStoreSync – serialize", () => {
  it("serializes all slices into a BackupDocument", () => {
    const tasks = makeSlice([{ id: "1", title: "Buy cake" }])
    const settings = makeSlice({ darkMode: false })

    const sync = createMultiStoreSync({
      version: 1,
      slices: { tasks: tasks.slice, settings: settings.slice },
    })

    const doc = sync.serialize()
    expect(doc.version).toBe(1)
    expect(doc.timestamp).toBeTypeOf("number")
    expect(doc.data.tasks).toEqual([{ id: "1", title: "Buy cake" }])
    expect(doc.data.settings).toEqual({ darkMode: false })
  })

  it("includes the current version", () => {
    const sync = createMultiStoreSync({
      version: 5,
      slices: { items: makeSlice([]).slice },
    })
    expect(sync.serialize().version).toBe(5)
  })

  it("reflects latest state at call time", () => {
    const tasks = makeSlice<string[]>([])
    const sync = createMultiStoreSync({ version: 1, slices: { tasks: tasks.slice } })

    tasks.set(["a", "b"])
    const doc = sync.serialize()
    expect(doc.data.tasks).toEqual(["a", "b"])
  })

  it("exposes version property", () => {
    const sync = createMultiStoreSync({ version: 3, slices: { x: makeSlice(0).slice } })
    expect(sync.version).toBe(3)
  })
})

// ── restore – same version ────────────────────────────────────────────────────

describe("createMultiStoreSync – restore (same version)", () => {
  it("restores all slices from a document", () => {
    const tasks = makeSlice<string[]>([])
    const settings = makeSlice({ darkMode: false })

    const sync = createMultiStoreSync({
      version: 1,
      slices: { tasks: tasks.slice, settings: settings.slice },
    })

    const doc: BackupDocument = {
      version: 1,
      timestamp: Date.now(),
      data: { tasks: ["task1", "task2"], settings: { darkMode: true } },
    }

    sync.restore(doc)
    expect(tasks.get()).toEqual(["task1", "task2"])
    expect(settings.get()).toEqual({ darkMode: true })
  })

  it("round-trips serialize → restore", () => {
    const tasks = makeSlice([{ id: "x" }])
    const sync = createMultiStoreSync({ version: 1, slices: { tasks: tasks.slice } })

    const doc = sync.serialize()
    tasks.set([])  // wipe
    sync.restore(doc)
    expect(tasks.get()).toEqual([{ id: "x" }])
  })

  it("ignores slices not present in the document (additive migration)", () => {
    const a = makeSlice("original")
    const b = makeSlice("original")
    const sync = createMultiStoreSync({ version: 2, slices: { a: a.slice, b: b.slice } })

    // Document from version 1 only has "a"
    sync.restore({ version: 2, timestamp: Date.now(), data: { a: "from-doc" } })
    expect(a.get()).toBe("from-doc")
    expect(b.get()).toBe("original")  // not overwritten
  })
})

// ── restore – migrations ──────────────────────────────────────────────────────

describe("createMultiStoreSync – restore (with migrations)", () => {
  it("runs migration when restoring an older document", () => {
    const tasks = makeSlice<string[]>([])
    const sync = createMultiStoreSync({
      version: 2,
      slices: { tasks: tasks.slice },
      migrations: {
        // v1 stored tasks as comma-separated strings; v2 is an array
        1: (data) => ({
          ...data,
          tasks: (data["tasks"] as string).split(","),
        }),
      },
    })

    sync.restore({
      version: 1,
      timestamp: Date.now(),
      data: { tasks: "alpha,beta,gamma" },
    })

    expect(tasks.get()).toEqual(["alpha", "beta", "gamma"])
  })

  it("runs multiple migrations in sequence", () => {
    const items = makeSlice<number[]>([])
    const sync = createMultiStoreSync({
      version: 3,
      slices: { items: items.slice },
      migrations: {
        1: (data) => ({ ...data, items: [1] }),
        2: (data) => ({ ...data, items: [...(data["items"] as number[]), 2] }),
      },
    })

    sync.restore({ version: 1, timestamp: Date.now(), data: { items: [] } })
    expect(items.get()).toEqual([1, 2])
  })

  it("skips migrations that are not in the chain", () => {
    const x = makeSlice(0)
    const fn1 = vi.fn((d: Record<string, unknown>) => ({ ...d, x: 1 }))
    const fn2 = vi.fn((d: Record<string, unknown>) => ({ ...d, x: 2 }))

    const sync = createMultiStoreSync({
      version: 4,
      slices: { x: x.slice },
      migrations: { 1: fn1, 3: fn2 },
    })

    sync.restore({ version: 3, timestamp: Date.now(), data: { x: 99 } })

    // Only migration 3 runs (doc is v3, target v4)
    expect(fn1).not.toHaveBeenCalled()
    expect(fn2).toHaveBeenCalledTimes(1)
    expect(x.get()).toBe(2)
  })

  it("throws when restoring a newer document version", () => {
    const sync = createMultiStoreSync({ version: 2, slices: { x: makeSlice(0).slice } })
    expect(() =>
      sync.restore({ version: 3, timestamp: Date.now(), data: {} }),
    ).toThrow("newer than current version")
  })

  it("wraps migration errors with context", () => {
    const sync = createMultiStoreSync({
      version: 2,
      slices: { x: makeSlice(0).slice },
      migrations: {
        1: () => { throw new Error("corrupt field") },
      },
    })

    expect(() =>
      sync.restore({ version: 1, timestamp: Date.now(), data: { x: 0 } }),
    ).toThrow("migration from version 1 to 2 failed: corrupt field")
  })
})

// ── edge cases ────────────────────────────────────────────────────────────────

describe("createMultiStoreSync – edge cases", () => {
  it("throws on invalid migration key", () => {
    expect(() =>
      createMultiStoreSync({
        version: 2,
        slices: { x: makeSlice(0).slice },
        migrations: { [-1]: (d) => d },
      }),
    ).toThrow("positive integer")
  })

  it("throws when restore receives non-object", () => {
    const sync = createMultiStoreSync({ version: 1, slices: { x: makeSlice(0).slice } })
    expect(() => sync.restore(null as unknown as BackupDocument)).toThrow()
  })

  it("throws on invalid document version", () => {
    const sync = createMultiStoreSync({ version: 2, slices: { x: makeSlice(0).slice } })
    expect(() =>
      sync.restore({ version: 0, timestamp: Date.now(), data: {} }),
    ).toThrow("invalid document version")
  })
})
