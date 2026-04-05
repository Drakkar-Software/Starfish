import { describe, it, expect } from "vitest"
import { matchesAllowedMime, isJsonCollection } from "../../src/router/mime.js"

describe("matchesAllowedMime", () => {
  it("matches exact MIME type", () => {
    expect(matchesAllowedMime("image/png", ["image/png"])).toBe(true)
  })

  it("matches wildcard pattern", () => {
    expect(matchesAllowedMime("image/png", ["image/*"])).toBe(true)
    expect(matchesAllowedMime("image/jpeg", ["image/*"])).toBe(true)
  })

  it("rejects non-matching type", () => {
    expect(matchesAllowedMime("text/plain", ["image/*"])).toBe(false)
  })

  it("handles case insensitivity", () => {
    expect(matchesAllowedMime("Image/PNG", ["image/png"])).toBe(true)
  })

  it("strips charset parameters", () => {
    expect(
      matchesAllowedMime("text/plain; charset=utf-8", ["text/plain"]),
    ).toBe(true)
  })

  it("returns false for empty content-type", () => {
    expect(matchesAllowedMime("", ["image/*"])).toBe(false)
  })
})

describe("isJsonCollection", () => {
  it("returns true when no MIME types specified", () => {
    expect(isJsonCollection(undefined)).toBe(true)
    expect(isJsonCollection([])).toBe(true)
  })

  it("returns true when application/json included", () => {
    expect(isJsonCollection(["application/json"])).toBe(true)
  })

  it("returns false for binary-only collection", () => {
    expect(isJsonCollection(["image/*"])).toBe(false)
  })
})
