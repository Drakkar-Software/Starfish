import { describe, it, expect, vi } from "vitest"
import { createGracefulShutdown } from "../src/lifecycle.js"

describe("createGracefulShutdown", () => {
  it("calls onShutdown callback", async () => {
    const onShutdown = vi.fn(async () => {})
    const handle = createGracefulShutdown({ onShutdown, signals: [] })
    await handle.shutdown()
    expect(onShutdown).toHaveBeenCalledOnce()
    handle.unregister()
  })

  it("runs plugin shutdown hooks on shutdown", async () => {
    const shutdown = vi.fn(async () => {})
    const plugin = { name: "test-plugin", shutdown }
    const handle = createGracefulShutdown({ plugins: [plugin], signals: [] })
    await handle.shutdown()
    expect(shutdown).toHaveBeenCalledOnce()
    handle.unregister()
  })

  it("only shuts down once (idempotent)", async () => {
    const onShutdown = vi.fn(async () => {})
    const handle = createGracefulShutdown({ onShutdown, signals: [] })
    await handle.shutdown()
    await handle.shutdown()
    expect(onShutdown).toHaveBeenCalledOnce()
    handle.unregister()
  })

  it("unregister removes signal handlers without error", () => {
    const handle = createGracefulShutdown({ signals: [] })
    // Should not throw
    handle.unregister()
  })
})
