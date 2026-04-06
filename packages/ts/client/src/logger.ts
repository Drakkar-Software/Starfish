/** Structured logger for sync operations. */
export interface SyncLogger {
  pullStart(store: string): void
  pullSuccess(store: string, durationMs: number): void
  pullError(store: string, error: string): void
  pushStart(store: string): void
  pushSuccess(store: string, durationMs: number): void
  pushError(store: string, error: string): void
  conflict(store: string, attempt: number): void
}

/** Console-based sync logger with structured output. */
export const consoleSyncLogger: SyncLogger = {
  pullStart: (s) => console.log(`[starfish:${s}] pull started`),
  pullSuccess: (s, ms) => console.log(`[starfish:${s}] pull OK (${ms}ms)`),
  pullError: (s, err) => console.error(`[starfish:${s}] pull failed: ${err}`),
  pushStart: (s) => console.log(`[starfish:${s}] push started`),
  pushSuccess: (s, ms) => console.log(`[starfish:${s}] push OK (${ms}ms)`),
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
