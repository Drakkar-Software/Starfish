import { describe, it, expect } from "vitest"
import { createMetricsCollector, consoleSyncLogger, noopSyncLogger } from "../src/logger.js"

describe("createMetricsCollector", () => {
  it("records pull metrics", () => {
    const collector = createMetricsCollector()
    collector.recordPull("settings", 100, { bytesTransferred: 1024 })
    collector.recordPull("settings", 200, { bytesTransferred: 2048 })

    const summary = collector.getSummary()
    expect(summary["settings"]).toBeDefined()
    expect(summary["settings"]!.totalPulls).toBe(2)
    expect(summary["settings"]!.totalBytes).toBe(3072)
    expect(summary["settings"]!.avgDurationMs).toBe(150)
  })

  it("records push metrics", () => {
    const collector = createMetricsCollector()
    collector.recordPush("settings", 50, { bytesTransferred: 512 })

    const summary = collector.getSummary()
    expect(summary["settings"]!.totalPushes).toBe(1)
    expect(summary["settings"]!.totalBytes).toBe(512)
  })

  it("records conflicts", () => {
    const collector = createMetricsCollector()
    collector.recordConflict("settings")
    collector.recordConflict("settings")

    const summary = collector.getSummary()
    expect(summary["settings"]!.totalConflicts).toBe(2)
  })

  it("tracks multiple stores independently", () => {
    const collector = createMetricsCollector()
    collector.recordPull("a", 100)
    collector.recordPull("b", 200)

    const summary = collector.getSummary()
    expect(Object.keys(summary)).toHaveLength(2)
    expect(summary["a"]!.totalPulls).toBe(1)
    expect(summary["b"]!.totalPulls).toBe(1)
  })

  it("resets all metrics", () => {
    const collector = createMetricsCollector()
    collector.recordPull("settings", 100)
    collector.reset()

    const summary = collector.getSummary()
    expect(Object.keys(summary)).toHaveLength(0)
  })
})

describe("SyncLogger with metrics", () => {
  it("consoleSyncLogger accepts optional metrics parameter", () => {
    // Should not throw
    consoleSyncLogger.pullSuccess("test", 100, { bytesTransferred: 1024, cacheHit: true })
    consoleSyncLogger.pushSuccess("test", 50, { bytesTransferred: 512 })
  })

  it("noopSyncLogger accepts optional metrics parameter", () => {
    // Should not throw
    noopSyncLogger.pullSuccess("test", 100, { bytesTransferred: 1024 })
    noopSyncLogger.pushSuccess("test", 50)
  })
})
