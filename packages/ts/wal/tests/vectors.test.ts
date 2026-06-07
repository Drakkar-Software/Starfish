import { describe, it, expect } from "vitest"
import { WalCrdt, compareClocks, type Json, type Op } from "../src/index.js"
import vectors from "../../../../tests/test-vectors/wal-crdt.json"

const sign = (n: number): number => (n < 0 ? -1 : n > 0 ? 1 : 0)

describe("wal-crdt conformance vectors", () => {
  it("clock total order matches the vector signs", () => {
    for (const c of vectors.clockOrder) {
      expect(sign(compareClocks(c.a, c.b))).toBe(c.sign)
    }
  })

  for (const f of vectors.fold) {
    it(`fold "${f.name}" converges (order-independent + idempotent)`, () => {
      const ops = f.ops as unknown as Op[]
      const expected = f.expected as Record<string, Json>

      const forward = new WalCrdt()
      forward.fold(ops)
      expect(forward.materialize()).toEqual(expected)

      const reversed = new WalCrdt()
      reversed.fold([...ops].reverse())
      expect(reversed.materialize()).toEqual(expected)

      const byClock = new WalCrdt()
      byClock.fold([...ops].sort((a, b) => compareClocks(a.clock, b.clock)))
      expect(byClock.materialize()).toEqual(expected)

      const twice = new WalCrdt()
      twice.fold(ops)
      twice.fold(ops)
      expect(twice.materialize()).toEqual(expected)

      const expectedText = (f as { expectedText?: Record<string, string> }).expectedText
      if (expectedText) {
        for (const [list, text] of Object.entries(expectedText)) {
          expect(forward.text(list)).toBe(text)
        }
      }
    })
  }
})
