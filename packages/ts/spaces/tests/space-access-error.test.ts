import { describe, it, expect } from "vitest"
import { SpaceAccessError } from "../src/space-access-error.js"

describe("SpaceAccessError", () => {
  it("is instanceof SpaceAccessError and Error", () => {
    const err = new SpaceAccessError("sp-123")
    expect(err).toBeInstanceOf(SpaceAccessError)
    expect(err).toBeInstanceOf(Error)
  })

  it("carries spaceId", () => {
    const err = new SpaceAccessError("sp-abc")
    expect(err.spaceId).toBe("sp-abc")
  })

  it("carries nodeId when provided", () => {
    const err = new SpaceAccessError("sp-abc", "obj-xyz")
    expect(err.nodeId).toBe("obj-xyz")
  })

  it("uses default message when no message provided", () => {
    const err = new SpaceAccessError("sp-abc", "obj-xyz")
    expect(err.message).toContain("sp-abc")
    expect(err.message).toContain("obj-xyz")
  })

  it("uses custom message when provided", () => {
    const err = new SpaceAccessError("sp-abc", undefined, "custom error")
    expect(err.message).toBe("custom error")
  })

  it("has correct name", () => {
    expect(new SpaceAccessError("sp-1").name).toBe("SpaceAccessError")
  })
})
