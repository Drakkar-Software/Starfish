/**
 * Drain driver for an {@link OutboxQueue}. Connectivity-agnostic by design: the
 * caller decides *when* to drain (typically on a reconnect signal — e.g. the
 * client's `createMobileLifecycle` `NetInfoModule`, or `window`'s `online` event),
 * keeping the queue itself free of any platform/connectivity dependency.
 */
import type { OutboxEntry, OutboxQueue } from "./queue.js"

export interface DrainOptions {
  /** Attempts before an entry escalates from auto-retry (`queued`) to `failed`. */
  maxAttempts?: number
}

export interface DrainResult {
  sent: number
  failed: number
}

/**
 * One drain pass: for each `queued` entry (oldest first), claim it, run `send`,
 * then `remove` on success or `recordFailure` on throw. `claim` is single-shot, so
 * concurrent drains never double-send the same entry. `failed` entries are skipped
 * (they await a manual `retry`). Returns how many were sent vs failed this pass.
 */
export async function drainOutbox<T>(
  queue: OutboxQueue<T>,
  send: (entry: OutboxEntry<T>) => Promise<void>,
  opts: DrainOptions = {},
): Promise<DrainResult> {
  const maxAttempts = opts.maxAttempts ?? 5
  let sent = 0
  let failed = 0
  // Snapshot the queued ids up front; claim guards against a racing drain.
  const queued = queue.get().filter((e) => e.status === "queued")
  for (const entry of queued) {
    if (!queue.claim(entry.id)) continue // already claimed by a concurrent drain
    try {
      await send(entry)
      queue.remove(entry.id)
      sent++
    } catch {
      const before = queue.get().find((e) => e.id === entry.id)
      queue.recordFailure(entry.id, maxAttempts)
      const after = queue.get().find((e) => e.id === entry.id)
      if (after?.status === "failed" && before?.status !== "failed") failed++
    }
  }
  return { sent, failed }
}
