import { describe, it, expect } from "vitest"
import {
  isServiceWorkerSupported,
  registerServiceWorker,
  unregisterServiceWorkers,
} from "../src/service-worker.js"

describe("isServiceWorkerSupported", () => {
  it("returns false in Node.js environment", () => {
    expect(isServiceWorkerSupported()).toBe(false)
  })
})

describe("registerServiceWorker", () => {
  it("returns null when not supported", async () => {
    const result = await registerServiceWorker("/sw.js")
    expect(result).toBeNull()
  })
})

describe("unregisterServiceWorkers", () => {
  it("returns false when not supported", async () => {
    const result = await unregisterServiceWorkers()
    expect(result).toBe(false)
  })
})
