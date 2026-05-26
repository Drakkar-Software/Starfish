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

describe("matchScopePath percent-encoding deny-evasion", () => {
  // Hono percent-decodes path params before composing the storage key, so a
  // request to `/push/col/_%6beyring` writes to `col/_keyring`. The scope match
  // must decode too or the deny is evaded. `%6b` and `%6B` both decode to `k`.
  it("denies an encoded keyring path (lowercase escape)", () => {
    expect(matchScopePath("col/_%6beyring", WRITER)).toBe(false)
  })

  it("denies an encoded keyring path (uppercase escape)", () => {
    expect(matchScopePath("col/_%6Beyring", WRITER)).toBe(false)
  })

  it("denies an encoded members path", () => {
    expect(matchScopePath("col/_%6dembers", WRITER)).toBe(false)
  })

  it("denies a fully-encoded keyring segment", () => {
    expect(matchScopePath("col/%5f%6b%65%79%72%69%6e%67", WRITER)).toBe(false)
  })

  it("leaves a malformed escape raw (still denied via the allow miss)", () => {
    // `%zz` is not a valid escape; decode is a no-op. The raw segment does not
    // match the keyring deny, but it also doesn't resolve to a real key.
    expect(matchScopePath("col/_%zzkeyring", WRITER)).toBe(true)
  })

  it("does not over-deny an encoded benign sibling", () => {
    // `col/_keyring%5fpublic` decodes to `col/_keyring_public` — a sibling, not
    // the keyring itself — so it stays allowed.
    expect(matchScopePath("col/_keyring%5fpublic", WRITER)).toBe(true)
  })
})

describe("matchScopePath collection prefix confusion", () => {
  it("does not match a substring-prefixed collection", () => {
    expect(matchScopePath("colAB/x", ["colA/**"])).toBe(false)
    expect(matchScopePath("colA/x", ["colA/**"])).toBe(true)
  })
})
