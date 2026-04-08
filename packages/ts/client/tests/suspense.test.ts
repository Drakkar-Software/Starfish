import { describe, it, expect } from "vitest"
import { createSuspenseResource } from "../src/bindings/suspense.js"

describe("createSuspenseResource", () => {
  it("throws a Promise on first read (pending state)", () => {
    const resource = createSuspenseResource(() => Promise.resolve(42))

    try {
      resource.read()
      expect.unreachable("should have thrown")
    } catch (thrown) {
      expect(thrown).toBeInstanceOf(Promise)
    }
  })

  it("returns value after resolution", async () => {
    const resource = createSuspenseResource(() => Promise.resolve(42))

    // Trigger the fetch by catching the thrown promise
    try {
      resource.read()
    } catch (thrown) {
      await thrown // Wait for resolution
    }

    // Now it should return the value synchronously
    expect(resource.read()).toBe(42)
  })

  it("throws error after rejection", async () => {
    const error = new Error("fail")
    const resource = createSuspenseResource(() => Promise.reject(error))

    try {
      resource.read()
    } catch (thrown) {
      if (thrown instanceof Promise) {
        await thrown.catch(() => {}) // Suppress unhandled rejection
      }
    }

    // Small delay to let the rejection settle
    await new Promise((r) => setTimeout(r, 10))

    expect(() => resource.read()).toThrow("fail")
  })

  it("only triggers fetcher once", async () => {
    let callCount = 0
    const resource = createSuspenseResource(async () => {
      callCount++
      return "data"
    })

    // Multiple reads while pending should not trigger multiple fetches
    const promises: Promise<void>[] = []
    for (let i = 0; i < 3; i++) {
      try {
        resource.read()
      } catch (thrown) {
        if (thrown instanceof Promise) promises.push(thrown)
      }
    }

    await Promise.all(promises)
    expect(callCount).toBe(1)
    expect(resource.read()).toBe("data")
  })
})
