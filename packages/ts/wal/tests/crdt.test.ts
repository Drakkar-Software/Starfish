import { describe, it, expect } from "vitest"
import { WalCrdt, compareClocks, type Op } from "../src/index.js"

function foldFresh(ops: Op[]): WalCrdt {
  const c = new WalCrdt()
  c.fold(ops)
  return c
}

/** Deterministic shuffles of `ops` for convergence/idempotence assertions. */
function permutations(ops: Op[]): Op[][] {
  return [
    ops,
    [...ops].reverse(),
    [...ops].sort((a, b) => compareClocks(a.clock, b.clock)),
    [...ops].sort((a, b) => compareClocks(b.clock, a.clock)),
  ]
}

describe("LWW register", () => {
  it("keeps the highest-clock write; ties break on replica id", () => {
    const ops: Op[] = [
      { t: "set", reg: "title", clock: { c: 1, r: "a" }, value: "draft" },
      { t: "set", reg: "title", clock: { c: 2, r: "a" }, value: "final" },
      { t: "set", reg: "title", clock: { c: 2, r: "b" }, value: "other" },
    ]
    for (const p of permutations(ops)) {
      expect(foldFresh(p).materialize()).toEqual({ title: "other" })
    }
  })

  it("delete tombstones, a higher-clock set resurrects", () => {
    const ops: Op[] = [
      { t: "set", reg: "x", clock: { c: 1, r: "a" }, value: "v1" },
      { t: "del", reg: "x", clock: { c: 2, r: "a" } },
      { t: "set", reg: "x", clock: { c: 3, r: "a" }, value: "v2" },
    ]
    for (const p of permutations(ops)) {
      expect(foldFresh(p).materialize()).toEqual({ x: "v2" })
    }
  })

  it("a stale (lower-clock) delete cannot erase a newer set", () => {
    const c = foldFresh([
      { t: "set", reg: "k", clock: { c: 5, r: "a" }, value: "keep" },
      { t: "del", reg: "k", clock: { c: 2, r: "b" } },
    ])
    expect(c.getRegister("k")).toBe("keep")
  })
})

describe("RGA sequence", () => {
  it("converges concurrent head inserts deterministically", () => {
    const ops: Op[] = [
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "A" },
      { t: "ins", list: "l", id: "1@b", after: "", clock: { c: 1, r: "b" }, value: "B" },
      { t: "ins", list: "l", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "C" },
    ]
    for (const p of permutations(ops)) {
      expect(foldFresh(p).listValues("l")).toEqual(["B", "A", "C"])
    }
  })

  it("delete keeps the element as an anchor for later inserts", () => {
    const ops: Op[] = [
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "x" },
      { t: "ins", list: "l", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "y" },
      { t: "rmv", list: "l", id: "1@a", clock: { c: 3, r: "a" } },
    ]
    for (const p of permutations(ops)) {
      expect(foldFresh(p).listValues("l")).toEqual(["y"])
    }
  })

  it("is idempotent: re-inserting an existing id is a no-op", () => {
    const ins: Op = { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "x" }
    const c = foldFresh([ins, ins, ins])
    expect(c.listValues("l")).toEqual(["x"])
  })

  it("tolerates a remove arriving before its insert", () => {
    const c = foldFresh([
      { t: "rmv", list: "l", id: "1@a", clock: { c: 2, r: "a" } },
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "x" },
    ])
    expect(c.listValues("l")).toEqual([])
  })

  it("converges a remove-before-insert whose element has a live descendant", () => {
    // Regression: the rmv-before-ins tombstone must not be mis-anchored at the
    // head and drag its live subtree (3@a) to the wrong position.
    const ops: Op[] = [
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "A" },
      { t: "ins", list: "l", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "B" },
      { t: "rmv", list: "l", id: "2@a", clock: { c: 3, r: "a" } },
      { t: "ins", list: "l", id: "3@a", after: "2@a", clock: { c: 4, r: "a" }, value: "C" },
    ]
    for (const p of permutations(ops)) {
      expect(foldFresh(p).listValues("l")).toEqual(["A", "C"])
    }
  })

  it("orders sibling inserts with identical clocks deterministically by id", () => {
    // Malformed ops (id decoupled from clock) sharing an exact clock must still
    // converge via the id tie-break, independent of fold order.
    const ops: Op[] = [
      { t: "ins", list: "l", id: "A", after: "", clock: { c: 1, r: "x" }, value: "first" },
      { t: "ins", list: "l", id: "B", after: "", clock: { c: 1, r: "x" }, value: "second" },
    ]
    expect(foldFresh(ops).listValues("l")).toEqual(["second", "first"])
    expect(foldFresh([...ops].reverse()).listValues("l")).toEqual(["second", "first"])
  })
})

describe("text CRDT", () => {
  it("materializes a sequence of single-char elements as a string", () => {
    const c = foldFresh([
      { t: "ins", list: "t", id: "1@a", after: "", clock: { c: 1, r: "a" }, value: "h" },
      { t: "ins", list: "t", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "i" },
    ])
    expect(c.text("t")).toBe("hi")
  })
})

describe("state export/import", () => {
  it("round-trips full state including tombstones", () => {
    const src = foldFresh([
      { t: "set", reg: "a", clock: { c: 1, r: "a" }, value: 1 },
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 2, r: "a" }, value: "x" },
      { t: "rmv", list: "l", id: "1@a", clock: { c: 3, r: "a" } },
    ])
    const restored = new WalCrdt()
    restored.importState(src.exportState())
    expect(restored.materialize()).toEqual(src.materialize())
    // A later insert after the tombstoned anchor still threads correctly.
    restored.apply({ t: "ins", list: "l", id: "2@a", after: "1@a", clock: { c: 4, r: "a" }, value: "y" })
    expect(restored.listValues("l")).toEqual(["y"])
  })

  it("clone is independent of the source", () => {
    const src = foldFresh([{ t: "set", reg: "a", clock: { c: 1, r: "a" }, value: 1 }])
    const copy = src.clone()
    copy.apply({ t: "set", reg: "a", clock: { c: 2, r: "a" }, value: 2 })
    expect(src.getRegister("a")).toBe(1)
    expect(copy.getRegister("a")).toBe(2)
  })

  it("deep-copies nested clocks so a mutated export cannot corrupt the source", () => {
    const src = foldFresh([
      { t: "set", reg: "a", clock: { c: 5, r: "a" }, value: 1 },
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 6, r: "a" }, value: "x" },
    ])
    const exported = src.exportState()
    // Mutate the exported clocks in place — the live document must be unaffected.
    exported.regs.a!.clock.c = 999
    exported.lists.l![0]!.clock.c = 999
    const after = src.exportState()
    expect(after.regs.a!.clock.c).toBe(5)
    expect(after.lists.l![0]!.clock.c).toBe(6)
  })

  it("exportState is unchanged by re-folding (idempotent at the state level)", () => {
    const ops: Op[] = [
      { t: "set", reg: "a", clock: { c: 1, r: "a" }, value: 1 },
      { t: "ins", list: "l", id: "1@a", after: "", clock: { c: 2, r: "a" }, value: "x" },
      { t: "rmv", list: "l", id: "1@a", clock: { c: 3, r: "a" } },
    ]
    const c = new WalCrdt()
    c.fold(ops)
    const before = JSON.stringify(c.exportState())
    c.fold(ops) // re-deliver the same batch
    expect(JSON.stringify(c.exportState())).toBe(before)
  })
})

describe("large documents", () => {
  it("materializes a long linear chain without a stack overflow", () => {
    // A long text run is a deep RGA chain; materialize must not recurse per node.
    const N = 50_000
    const ops: Op[] = []
    for (let i = 0; i < N; i++) {
      ops.push({
        t: "ins",
        list: "body",
        id: `${i}@a`,
        after: i === 0 ? "" : `${i - 1}@a`,
        clock: { c: i + 1, r: "a" },
        value: "x",
      })
    }
    const c = new WalCrdt()
    c.fold(ops)
    const values = c.listValues("body")
    expect(values).toHaveLength(N)
    expect(c.text("body")).toHaveLength(N)
  })
})
