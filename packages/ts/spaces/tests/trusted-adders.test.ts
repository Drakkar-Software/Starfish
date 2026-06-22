/**
 * Tests for `computeOwnerTrustedAdders` in starfish-identities.
 */
import { describe, it, expect } from "vitest"
import { computeOwnerTrustedAdders } from "@drakkar.software/starfish-identities"

describe("computeOwnerTrustedAdders", () => {
  it("returns [self] when owner equals self", () => {
    const self = "aabb"
    expect(computeOwnerTrustedAdders(self, self)).toEqual([self])
  })

  it("returns [owner, self] when owner differs from self", () => {
    const owner = "aabb"
    const self = "ccdd"
    expect(computeOwnerTrustedAdders(owner, self)).toEqual([owner, self])
  })

  it("treats undefined owner as self", () => {
    const self = "aabb"
    expect(computeOwnerTrustedAdders(undefined, self)).toEqual([self])
  })
})
