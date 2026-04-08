import { describe, it, expect } from "vitest"
import { isExpired } from "../src/ttl.js"

describe("isExpired", () => {
  it("returns false for timestamp 0 (never written)", () => {
    expect(isExpired(0, 60_000)).toBe(false)
  })

  it("returns false for recent documents", () => {
    expect(isExpired(Date.now() - 1000, 60_000)).toBe(false)
  })

  it("returns true for old documents", () => {
    expect(isExpired(Date.now() - 120_000, 60_000)).toBe(true)
  })

  it("edge case: exactly at TTL boundary", () => {
    const now = Date.now()
    expect(isExpired(now - 60_001, 60_000)).toBe(true)
  })

  it("returns false for non-positive TTL (never expires)", () => {
    expect(isExpired(Date.now() - 999_999_999, 0)).toBe(false)
    expect(isExpired(Date.now() - 999_999_999, -1)).toBe(false)
  })
})
