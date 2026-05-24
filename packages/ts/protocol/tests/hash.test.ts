import { describe, it, expect } from "vitest"
import { stableStringify, computeHash } from "../src/hash.js"
import vectors from "../../../../tests/test-vectors/hash.json"

describe("stableStringify", () => {
  for (const { input, expected } of vectors.stableStringify) {
    it(`stableStringify(${JSON.stringify(input)}) === ${expected}`, () => {
      expect(stableStringify(input)).toBe(expected)
    })
  }
})

describe("computeHash", () => {
  for (const { input, stableJson, expectedHash } of vectors.computeHash) {
    it(`hash of ${JSON.stringify(input)}`, async () => {
      expect(stableStringify(input)).toBe(stableJson)
      const hash = await computeHash(input as Record<string, unknown>)
      expect(hash).toBe(expectedHash)
    })
  }
})

describe("non-finite numbers", () => {
  // NaN/±Infinity aren't valid JSON; both languages render them as "null"
  // (JS via JSON.stringify, Python via _js_number) — a deliberate cross-language
  // invariant no JSON vector can encode, so it lives as a code-level test.
  it("NaN/±Infinity serialize as null and hash identically", async () => {
    expect(stableStringify(NaN)).toBe("null")
    expect(stableStringify(Infinity)).toBe("null")
    expect(stableStringify(-Infinity)).toBe("null")
    // Recursion path: non-finite nested in containers.
    expect(stableStringify({ a: NaN, b: [Infinity] })).toBe('{"a":null,"b":[null]}')
    // All three collapse to "null" ⇒ identical document hash — the property sync relies on.
    const h1 = await computeHash({ x: NaN })
    const h2 = await computeHash({ x: Infinity })
    const h3 = await computeHash({ x: -Infinity })
    expect(h1).toBe(h2)
    expect(h2).toBe(h3)
  })
})
