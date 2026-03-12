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
