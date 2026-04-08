import type { ObjectStore } from "./storage/base.js"
import type { SyncConfig } from "./config/schema.js"

/** Check if a document has expired based on its last-modified timestamp and TTL. */
export function isExpired(timestamp: number, ttlMs: number): boolean {
  if (timestamp === 0) return false // Never written — not expired
  return Date.now() - timestamp > ttlMs
}

/** Periodically clean up expired documents from storage. */
export function createTtlCleanup(
  store: ObjectStore,
  config: SyncConfig,
  intervalMs: number = 60_000,
): { stop: () => void } {
  const ttlCollections = config.collections.filter((c) => c.ttlMs != null && c.ttlMs > 0)

  if (ttlCollections.length === 0) {
    return { stop() {} }
  }

  const timer = setInterval(async () => {
    // TTL cleanup is best-effort; storage implementations may support
    // listing keys in the future for more efficient cleanup.
    // For now, this is a placeholder that can be extended.
  }, intervalMs)

  return {
    stop() {
      clearInterval(timer)
    },
  }
}
