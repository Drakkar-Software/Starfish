import { describe, it, expect } from "vitest"
import { maxLeafTimestamp } from "../../src/protocol/timestamps.js"

describe("maxLeafTimestamp", () => {
  it("returns a plain number leaf", () => {
    expect(maxLeafTimestamp(42)).toBe(42)
  })

  it("returns max of nested object", () => {
    expect(maxLeafTimestamp({ a: 10, b: 20 })).toBe(20)
  })

  it("returns 0 for null/undefined", () => {
    expect(maxLeafTimestamp(null)).toBe(0)
    expect(maxLeafTimestamp(undefined)).toBe(0)
  })

  it("returns max of number[] leaf (per-item appendOnly timestamps)", () => {
    expect(maxLeafTimestamp([100, 200, 300])).toBe(300)
  })

  it("returns 0 for empty number[] leaf", () => {
    expect(maxLeafTimestamp([])).toBe(0)
  })

  it("handles nested object containing a number[] leaf", () => {
    expect(maxLeafTimestamp({ items: [50, 150, 250], meta: 10 })).toBe(250)
  })
})
