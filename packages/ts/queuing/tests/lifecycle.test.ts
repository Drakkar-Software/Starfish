import { describe, it, expect, vi } from "vitest"
import { createGracefulShutdown } from "@drakkar.software/starfish-server"
import { createQueuingServerPlugin, type Queue } from "../src/index.js"

describe("queuing plugin — shutdown closes the queue", () => {
  it("createGracefulShutdown invokes the plugin's shutdown hook, which closes the queue", async () => {
    const close = vi.fn(async () => {})
    const queue: Queue = { publish: vi.fn(async () => {}), close }
    const plugin = createQueuingServerPlugin({ queue, collections: {} })

    const handle = createGracefulShutdown({ plugins: [plugin], signals: [] })
    await handle.shutdown()

    expect(close).toHaveBeenCalledOnce()
    handle.unregister()
  })

  it("shutdown is a no-op when the queue has no close()", async () => {
    const queue: Queue = { publish: vi.fn(async () => {}) }
    const plugin = createQueuingServerPlugin({ queue, collections: {} })

    const handle = createGracefulShutdown({ plugins: [plugin], signals: [] })
    await expect(handle.shutdown()).resolves.toBeUndefined()
    handle.unregister()
  })
})
