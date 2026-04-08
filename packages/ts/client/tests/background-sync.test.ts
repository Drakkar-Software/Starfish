import { describe, it, expect } from "vitest"
import { isBackgroundSyncSupported, registerBackgroundSync } from "../src/background-sync.js"

describe("isBackgroundSyncSupported", () => {
  it("returns false in Node.js environment", () => {
    expect(isBackgroundSyncSupported()).toBe(false)
  })
})

describe("registerBackgroundSync", () => {
  it("returns false when not supported", async () => {
    const result = await registerBackgroundSync()
    expect(result).toBe(false)
  })

  it("returns false with custom tag when not supported", async () => {
    const result = await registerBackgroundSync({ tag: "custom-sync" })
    expect(result).toBe(false)
  })
})
