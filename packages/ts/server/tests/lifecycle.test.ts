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

  it("stops replica manager on shutdown", async () => {
    const replicaManager = { stop: vi.fn(async () => {}) } as any
    const handle = createGracefulShutdown({ replicaManager, signals: [] })
    await handle.shutdown()
    expect(replicaManager.stop).toHaveBeenCalledOnce()
    handle.unregister()
  })

  it("closes queue on shutdown", async () => {
    const queue = { close: vi.fn(async () => {}), publish: vi.fn() } as any
    const handle = createGracefulShutdown({ queue, signals: [] })
    await handle.shutdown()
    expect(queue.close).toHaveBeenCalledOnce()
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
