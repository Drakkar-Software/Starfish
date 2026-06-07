import { describe, it, expect } from "vitest"
import {
  compareClocks,
  clockGreater,
  compareCodePoints,
  LamportClock,
  deriveReplicaId,
} from "../src/index.js"

describe("clock total order", () => {
  it("orders by counter first", () => {
    expect(compareClocks({ c: 1, r: "z" }, { c: 2, r: "a" })).toBeLessThan(0)
    expect(clockGreater({ c: 3, r: "a" }, { c: 2, r: "z" })).toBe(true)
  })

  it("breaks counter ties by replica id (code-point order)", () => {
    expect(compareClocks({ c: 2, r: "a" }, { c: 2, r: "b" })).toBeLessThan(0)
    expect(compareClocks({ c: 2, r: "b" }, { c: 2, r: "a" })).toBeGreaterThan(0)
  })

  it("returns 0 only for identical clocks (no ties given unique replica ids)", () => {
    expect(compareClocks({ c: 7, r: "abc" }, { c: 7, r: "abc" })).toBe(0)
  })

  it("compareCodePoints matches code-point (not UTF-16) order", () => {
    // U+E000 (BMP, > surrogate range) vs U+10000 (non-BMP). Code-point order
    // puts U+E000 first; naive UTF-16 comparison would invert this.
    expect(compareCodePoints("", "\u{10000}")).toBeLessThan(0)
  })
})

describe("LamportClock", () => {
  it("ticks monotonically and stamps the replica id", () => {
    const clk = new LamportClock("r1")
    expect(clk.tick()).toEqual({ c: 1, r: "r1" })
    expect(clk.tick()).toEqual({ c: 2, r: "r1" })
    expect(clk.value).toBe(2)
  })

  it("advances past observed clocks (Lamport receive rule)", () => {
    const clk = new LamportClock("r1")
    clk.observe({ c: 10, r: "other" })
    expect(clk.tick()).toEqual({ c: 11, r: "r1" })
  })
})

describe("deriveReplicaId", () => {
  it("combines author key and session nonce for per-session uniqueness", () => {
    expect(deriveReplicaId("pub", "sess-1")).not.toBe(deriveReplicaId("pub", "sess-2"))
  })
})
