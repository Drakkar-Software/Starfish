import { describe, it, expect, vi } from "vitest"
import { consoleSyncLogger, noopSyncLogger } from "../src/logger.js"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import type { SyncLogger } from "../src/logger.js"

function mockClient(overrides: {
  pull?: () => Promise<{ data: Record<string, unknown>; hash: string; timestamp: number }>
  push?: () => Promise<{ hash: string; timestamp: number }>
} = {}) {
  return {
    pull: overrides.pull ?? vi.fn(async () => ({
      data: { key: "value" },
      hash: "abc123",
      timestamp: 1000,
    })),
    push: overrides.push ?? vi.fn(async () => ({
      hash: "def456",
      timestamp: 2000,
    })),
  } as unknown as StarfishClient
}

function mockLogger(): SyncLogger & { calls: string[] } {
  const calls: string[] = []
  return {
    calls,
    pullStart: vi.fn((s) => calls.push(`pullStart:${s}`)),
    pullSuccess: vi.fn((s) => calls.push(`pullSuccess:${s}`)),
    pullError: vi.fn((s) => calls.push(`pullError:${s}`)),
    pushStart: vi.fn((s) => calls.push(`pushStart:${s}`)),
    pushSuccess: vi.fn((s) => calls.push(`pushSuccess:${s}`)),
    pushError: vi.fn((s) => calls.push(`pushError:${s}`)),
    conflict: vi.fn((s, n) => calls.push(`conflict:${s}:${n}`)),
  }
}

describe("consoleSyncLogger", () => {
  it("logs to console without throwing", () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {})
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {})
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {})

    consoleSyncLogger.pullStart("test")
    consoleSyncLogger.pullSuccess("test", 42)
    consoleSyncLogger.pullError("test", "oops")
    consoleSyncLogger.pushStart("test")
    consoleSyncLogger.pushSuccess("test", 10)
    consoleSyncLogger.pushError("test", "fail")
    consoleSyncLogger.conflict("test", 1)

    expect(logSpy).toHaveBeenCalledTimes(4)
    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(errorSpy).toHaveBeenCalledTimes(2)

    logSpy.mockRestore()
    warnSpy.mockRestore()
    errorSpy.mockRestore()
  })
})

describe("noopSyncLogger", () => {
  it("does not throw for any method", () => {
    expect(() => {
      noopSyncLogger.pullStart("x")
      noopSyncLogger.pullSuccess("x", 0)
      noopSyncLogger.pullError("x", "e")
      noopSyncLogger.pushStart("x")
      noopSyncLogger.pushSuccess("x", 0)
      noopSyncLogger.pushError("x", "e")
      noopSyncLogger.conflict("x", 1)
    }).not.toThrow()
  })
})

describe("SyncManager logger integration", () => {
  it("calls logger on successful pull", async () => {
    const logger = mockLogger()
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/users/abc/settings",
      pushPath: "/push/users/abc/settings",
      logger,
    })

    await sync.pull()

    expect(logger.pullStart).toHaveBeenCalledWith("settings")
    expect(logger.pullSuccess).toHaveBeenCalledWith("settings", expect.any(Number))
  })

  it("calls logger on pull error", async () => {
    const logger = mockLogger()
    const sync = new SyncManager({
      client: mockClient({ pull: async () => { throw new Error("network") } }),
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger,
    })

    await expect(sync.pull()).rejects.toThrow("network")
    expect(logger.pullError).toHaveBeenCalledWith("test", "network")
  })

  it("calls logger on successful push", async () => {
    const logger = mockLogger()
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger,
    })

    await sync.push({ a: 1 })

    expect(logger.pushStart).toHaveBeenCalledWith("test")
    expect(logger.pushSuccess).toHaveBeenCalledWith("test", expect.any(Number))
  })

  it("calls logger on push error", async () => {
    const logger = mockLogger()
    const sync = new SyncManager({
      client: mockClient({ push: async () => { throw new Error("server down") } }),
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger,
    })

    await expect(sync.push({ a: 1 })).rejects.toThrow("server down")
    expect(logger.pushError).toHaveBeenCalledWith("test", "server down")
  })

  it("uses custom name when provided", async () => {
    const logger = mockLogger()
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger,
      name: "my-store",
    })

    await sync.pull()
    expect(logger.pullStart).toHaveBeenCalledWith("my-store")
  })

  it("works without logger (no errors)", async () => {
    const sync = new SyncManager({
      client: mockClient(),
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    await expect(sync.pull()).resolves.toBeDefined()
    await expect(sync.push({ x: 1 })).resolves.toBeDefined()
  })
})
