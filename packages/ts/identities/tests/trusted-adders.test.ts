import { describe, it, expect } from "vitest"
import { computeOwnerTrustedAdders } from "../src/trusted-adders.js"

describe("computeOwnerTrustedAdders", () => {
  it("returns [self] when owner equals self (single-device case)", () => {
    const key = "aaabbb"
    expect(computeOwnerTrustedAdders(key, key)).toEqual([key])
  })

  it("returns [owner, self] when owner differs (paired-device case)", () => {
    expect(computeOwnerTrustedAdders("owner", "device")).toEqual(["owner", "device"])
  })

  it("treats undefined owner as self", () => {
    const self = "cccddd"
    expect(computeOwnerTrustedAdders(undefined, self)).toEqual([self])
  })

  it("preserves input order: owner first, self second", () => {
    const [first, second] = computeOwnerTrustedAdders("root", "paired")
    expect(first).toBe("root")
    expect(second).toBe("paired")
  })
})
