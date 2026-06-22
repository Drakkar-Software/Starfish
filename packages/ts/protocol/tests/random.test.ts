/**
 * Tests for randomId() and slugify().
 */
import { describe, it, expect } from "vitest"
import { randomId, slugify } from "../src/random.js"

describe("randomId", () => {
  it("returns a 32-character hex string", () => {
    const id = randomId()
    expect(id).toMatch(/^[0-9a-f]{32}$/)
  })

  it("generates unique ids on successive calls", () => {
    const ids = new Set(Array.from({ length: 100 }, () => randomId()))
    expect(ids.size).toBe(100)
  })

  it("only contains lowercase hex characters", () => {
    for (let i = 0; i < 20; i++) {
      expect(randomId()).toMatch(/^[0-9a-f]+$/)
    }
  })
})

describe("slugify", () => {
  it("lowercases and replaces non-alphanumeric runs with a single dash", () => {
    expect(slugify("Hello World")).toBe("hello-world")
    expect(slugify("Hello   World")).toBe("hello-world")
    expect(slugify("Hello! World?")).toBe("hello-world")
  })

  it("strips leading and trailing dashes", () => {
    expect(slugify("  hello  ")).toBe("hello")
    expect(slugify("--hello--")).toBe("hello")
  })

  it("caps output at 40 characters", () => {
    const long = "a".repeat(50)
    expect(slugify(long)).toHaveLength(40)
  })

  it("returns the fallback when the name strips to empty", () => {
    expect(slugify("   ")).toBe("item")
    expect(slugify("!!!", "doc")).toBe("doc")
    expect(slugify("---")).toBe("item")
  })

  it("uses a custom fallback", () => {
    expect(slugify("", "room")).toBe("room")
    expect(slugify("!!!!", "page")).toBe("page")
  })

  it("handles Unicode by collapsing non-ASCII runs", () => {
    expect(slugify("Héllo Wörld")).toBe("h-llo-w-rld")
  })

  it("produces only [a-z0-9-] characters", () => {
    const inputs = ["My Café", "résumé", "αβγ", "test_value", "a.b.c"]
    for (const input of inputs) {
      expect(slugify(input)).toMatch(/^[a-z0-9-]+$/)
    }
  })
})
