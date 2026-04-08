/** Extended metrics for sync operations. */
export interface SyncMetrics {
  bytesTransferred?: number
  compressedSize?: number
  conflictCount?: number
  retryCount?: number
  cacheHit?: boolean
}

/** Structured logger for sync operations. */
export interface SyncLogger {
  pullStart(store: string): void
  pullSuccess(store: string, durationMs: number, metrics?: SyncMetrics): void
  pullError(store: string, error: string): void
  pushStart(store: string): void
  pushSuccess(store: string, durationMs: number, metrics?: SyncMetrics): void
  pushError(store: string, error: string): void
  conflict(store: string, attempt: number): void
}

/** Console-based sync logger with structured output. */
export const consoleSyncLogger: SyncLogger = {
  pullStart: (s) => console.log(`[starfish:${s}] pull started`),
  pullSuccess: (s, ms, m) => {
    let msg = `[starfish:${s}] pull OK (${ms}ms)`
    if (m?.bytesTransferred) msg += ` ${m.bytesTransferred}B`
    if (m?.cacheHit) msg += ` (cache hit)`
    console.log(msg)
  },
  pullError: (s, err) => console.error(`[starfish:${s}] pull failed: ${err}`),
  pushStart: (s) => console.log(`[starfish:${s}] push started`),
  pushSuccess: (s, ms, m) => {
    let msg = `[starfish:${s}] push OK (${ms}ms)`
    if (m?.bytesTransferred) msg += ` ${m.bytesTransferred}B`
    console.log(msg)
  },
  pushError: (s, err) => console.error(`[starfish:${s}] push failed: ${err}`),
  conflict: (s, n) => console.warn(`[starfish:${s}] conflict (attempt ${n})`),
}

/** Silent sync logger (no output). */
export const noopSyncLogger: SyncLogger = {
  pullStart: () => {},
  pullSuccess: () => {},
  pullError: () => {},
  pushStart: () => {},
  pushSuccess: () => {},
  pushError: () => {},
  conflict: () => {},
}

/** Accumulated metrics for a single store. */
interface StoreSummary {
  totalPulls: number
  totalPushes: number
  totalDurationMs: number
  totalBytes: number
  totalConflicts: number
}

/** Collects sync metrics over time. */
export interface MetricsCollector {
  recordPull(name: string, durationMs: number, metrics?: SyncMetrics): void
  recordPush(name: string, durationMs: number, metrics?: SyncMetrics): void
  recordConflict(name: string): void
  getSummary(): Record<string, { totalPulls: number; totalPushes: number; avgDurationMs: number; totalBytes: number; totalConflicts: number }>
  reset(): void
}

/** Create a metrics collector that accumulates sync statistics. */
export function createMetricsCollector(): MetricsCollector {
  const stores = new Map<string, StoreSummary>()

  function ensureStore(name: string): StoreSummary {
    let s = stores.get(name)
    if (!s) {
      s = { totalPulls: 0, totalPushes: 0, totalDurationMs: 0, totalBytes: 0, totalConflicts: 0 }
      stores.set(name, s)
    }
    return s
  }

  return {
    recordPull(name, durationMs, metrics) {
      const s = ensureStore(name)
      s.totalPulls++
      s.totalDurationMs += durationMs
      if (metrics?.bytesTransferred) s.totalBytes += metrics.bytesTransferred
    },
    recordPush(name, durationMs, metrics) {
      const s = ensureStore(name)
      s.totalPushes++
      s.totalDurationMs += durationMs
      if (metrics?.bytesTransferred) s.totalBytes += metrics.bytesTransferred
    },
    recordConflict(name) {
      ensureStore(name).totalConflicts++
    },
    getSummary() {
      const result: Record<string, { totalPulls: number; totalPushes: number; avgDurationMs: number; totalBytes: number; totalConflicts: number }> = {}
      for (const [name, s] of stores) {
        const totalOps = s.totalPulls + s.totalPushes
        result[name] = {
          totalPulls: s.totalPulls,
          totalPushes: s.totalPushes,
          avgDurationMs: totalOps > 0 ? Math.round(s.totalDurationMs / totalOps) : 0,
          totalBytes: s.totalBytes,
          totalConflicts: s.totalConflicts,
        }
      }
      return result
    },
    reset() {
      stores.clear()
    },
  }
}
