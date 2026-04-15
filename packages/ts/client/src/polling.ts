/** Minimal state needed by polling utilities. */
export interface PollableState {
  online: boolean
  syncing: boolean
}

const DEFAULT_INTERVALS: Record<string, number> = {
  "slow-2g": 120_000,
  "2g": 60_000,
  "3g": 30_000,
  "4g": 10_000,
}

const DEFAULT_FALLBACK_MS = 15_000

/**
 * Start periodic pulling at a fixed interval.
 * Skips pulls when offline or already syncing.
 * Returns a cleanup function that stops polling.
 */
export function startPolling(
  pullFn: () => Promise<void>,
  getState: () => PollableState,
  intervalMs = 30_000,
): () => void {
  const timer = setInterval(() => {
    const { online, syncing } = getState()
    if (online && !syncing) pullFn().catch((err) => { console.error("[Starfish] poll failed:", err) })
  }, intervalMs)

  return () => clearInterval(timer)
}

export interface AdaptivePollingOptions {
  /** Override the base interval in ms. If set, skips network quality detection. */
  intervalMs?: number
  /** Custom mapping from effectiveType to interval in ms. */
  intervals?: Record<string, number>
}

export interface AdaptivePollingControls {
  pause: () => void
  resume: () => void
  stop: () => void
}

/**
 * Start polling with adaptive intervals based on network quality.
 * Uses the Network Information API (`navigator.connection.effectiveType`) when available.
 * Returns controls to pause, resume, or stop polling.
 */
export function startAdaptivePolling(
  pullFn: () => Promise<void>,
  getState: () => PollableState,
  options?: AdaptivePollingOptions,
): AdaptivePollingControls {
  let intervalMs: number

  if (options?.intervalMs != null) {
    intervalMs = options.intervalMs
  } else {
    const intervals = options?.intervals ?? DEFAULT_INTERVALS
    let effectiveType: string | undefined
    if (typeof navigator !== "undefined" && "connection" in navigator) {
      effectiveType = (navigator as unknown as { connection: { effectiveType?: string } }).connection.effectiveType
    }
    intervalMs = (effectiveType != null ? intervals[effectiveType] : undefined) ?? DEFAULT_FALLBACK_MS
  }

  let paused = false

  const timer = setInterval(() => {
    if (paused) return
    const { online, syncing } = getState()
    if (online && !syncing) pullFn().catch((err) => { console.error("[Starfish] adaptive poll failed:", err) })
  }, intervalMs)

  return {
    pause: () => { paused = true },
    resume: () => { paused = false },
    stop: () => clearInterval(timer),
  }
}
