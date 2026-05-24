import { describe, it, expect } from "vitest"
import { matchScopePath } from "../../src/router/cap-resolver.js"

// Regression coverage for the deny-evasion gap: an owner-only deny such as
// `!col/_keyring` must not be bypassable with a superstring request path —
// a trailing slash, an extra path segment, a `.` segment, or a double slash.
// A deny also covers descendants of the denied path.
const WRITER = ["col/**", "!col/_keyring", "!col/_members"]

describe("matchScopePath deny-rule semantics", () => {
  it("allows a normal document", () => {
    expect(matchScopePath("col/doc", WRITER)).toBe(true)
  })

  it("denies the exact keyring path", () => {
    expect(matchScopePath("col/_keyring", WRITER)).toBe(false)
  })

  it("denies keyring with a trailing slash", () => {
    expect(matchScopePath("col/_keyring/", WRITER)).toBe(false)
  })

  it("denies keyring with an extra segment", () => {
    expect(matchScopePath("col/_keyring/x", WRITER)).toBe(false)
  })

  it("denies keyring reached via a '.' segment", () => {
    expect(matchScopePath("col/./_keyring", WRITER)).toBe(false)
  })

  it("denies keyring reached via a double slash", () => {
    expect(matchScopePath("col//_keyring", WRITER)).toBe(false)
  })

  it("denies a descendant of the members directory", () => {
    expect(matchScopePath("col/_members/anything", WRITER)).toBe(false)
  })

  it("does not over-deny a similarly named sibling", () => {
    expect(matchScopePath("col/_keyring_public", WRITER)).toBe(true)
    expect(matchScopePath("col/_memberslist", WRITER)).toBe(true)
  })

  it("treats empty/undefined scope as unrestricted", () => {
    expect(matchScopePath("anything/at/all", undefined)).toBe(true)
    expect(matchScopePath("anything", [])).toBe(true)
  })

  it("denies when no allow rule matches", () => {
    expect(matchScopePath("other/doc", WRITER)).toBe(false)
  })
})
