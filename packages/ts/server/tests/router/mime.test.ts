import { describe, it, expect } from "vitest"
import { matchesAllowedMime, isJsonCollection } from "../../src/router/mime.js"

describe("matchesAllowedMime", () => {
  it("matches an exact media type", () => {
    expect(matchesAllowedMime("application/json", ["application/json"])).toBe(true)
    expect(matchesAllowedMime("image/png", ["application/json"])).toBe(false)
  })

  it("matches a subtype wildcard and a full wildcard", () => {
    expect(matchesAllowedMime("image/png", ["image/*"])).toBe(true)
    expect(matchesAllowedMime("image/png", ["*/*"])).toBe(true)
    expect(matchesAllowedMime("text/plain", ["image/*"])).toBe(false)
  })

  it("strips content-type parameters and is case-insensitive", () => {
    expect(matchesAllowedMime("application/JSON; charset=utf-8", ["application/json"])).toBe(true)
    expect(matchesAllowedMime("IMAGE/PNG", ["image/*"])).toBe(true)
  })

  it("treats only a whole '*' component as a wildcard, not a partial glob", () => {
    // Component-only matching: "image/p*" is a literal subtype, not a glob, so it
    // does NOT match "image/png". The Python matcher is converged to the same
    // component-only semantics (mime.py) — see test_mime.py.
    expect(matchesAllowedMime("image/png", ["image/p*"])).toBe(false)
  })
})

describe("isJsonCollection", () => {
  it("is true only when application/json is in the allowed list", () => {
    expect(isJsonCollection(["application/json"])).toBe(true)
    expect(isJsonCollection(["image/png"])).toBe(false)
    expect(isJsonCollection(["application/JSON"])).toBe(true) // case-insensitive
  })
})
