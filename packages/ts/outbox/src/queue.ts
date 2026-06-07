/**
 * A durable, per-identity offline **write-queue** — the client-side complement to
 * the server-side `queuing` extension. It queues opaque items `<T>` and the caller
 * owns *what* a queued item is and *how* it is sent.
 *
 * Invariants (carried over from the proven implementation):
 *  - **Dedup by id.** `enqueue(id, …)` ignores an id already queued. The id is the
 *    caller's to thread into the real write so the resulting record can be matched
 *    and the entry dropped without a duplicate.
 *  - **Removed only on confirmed success.** {@link drainOutbox} `remove`s an entry
 *    only after `send` resolves; a throw leaves it `queued` (auto-retry until
 *    `maxAttempts`) then `failed` (manual `retry`).
 *  - **Persisted per identity.** Write-through to a {@link LocalCache} under the
 *    key bound by {@link OutboxQueue.hydrate}, so a queued item survives a restart.
 *  - **Crash-safe claim.** A claimed-but-unresolved `sending` entry is reset to
 *    `queued` on the next `hydrate`, and `claim` is single-shot so two concurrent
 *    drains never double-send.
 */

/** Minimal async key/value cache — localStorage / AsyncStorage / IndexedDB wrapper. */
export interface LocalCache {
  getItem(key: string): Promise<string | null>
  setItem(key: string, value: string): Promise<void>
  removeItem(key: string): Promise<void>
}

export type OutboxStatus = "queued" | "sending" | "failed"

/** One queued write: the caller's opaque `item` plus queue bookkeeping. */
export interface OutboxEntry<T> {
  id: string
  item: T
  status: OutboxStatus
  attempts: number
  enqueuedAt: number
}

export interface OutboxQueue<T> {
  /** The current entries (synchronous snapshot, append/ts order). */
  get(): OutboxEntry<T>[]
  /** Subscribe to queue changes; returns an unsubscribe fn. */
  subscribe(listener: () => void): () => void
  /** Bind to a cache key and load the persisted queue (resetting stuck `sending`
   *  entries to `queued`). Call on sign-in / identity switch. */
  hydrate(cacheKey: string): Promise<void>
  /** Drop all in-memory state and unbind the cache key (sign-out). */
  clear(): void
  /** Append an entry. Dedup by id — a re-enqueue of a live id is ignored. */
  enqueue(id: string, item: T, ts?: number): void
  /** Mark `id` `sending`; returns false if already claimed (first claim wins). */
  claim(id: string): boolean
  /** Sent successfully — drop it. */
  remove(id: string): void
  /** Bump attempts and escalate to `failed` only at `maxAttempts`; below that keep
   *  it `queued` so a transient/offline blip auto-retries. */
  recordFailure(id: string, maxAttempts: number): void
  /** Force `failed` (and bump attempts) regardless of the attempt count. */
  markFailed(id: string): void
  /** Re-queue an entry (manual retry of a `failed` one, or backing a claimed-but-
   *  unsent entry out of `sending`). Leaves `attempts` untouched. */
  retry(id: string): void
  /** Entries matching `predicate` (e.g. by some field of `item`), order preserved. */
  pending(predicate?: (item: T) => boolean): OutboxEntry<T>[]
}

/** A crash/reload can leave an entry stuck `sending`; reset those to `queued`. */
export function resetSendingToQueued<T>(items: OutboxEntry<T>[]): OutboxEntry<T>[] {
  return items.map((i) => (i.status === "sending" ? { ...i, status: "queued" as const } : i))
}

export function createOutboxQueue<T>(cache: LocalCache): OutboxQueue<T> {
  let items: OutboxEntry<T>[] = []
  let cacheKey: string | null = null
  const listeners = new Set<() => void>()

  // Best-effort persistence: the `setItem` call is issued synchronously (in commit
  // order) but NOT awaited, so the in-memory mutation + notify never block on disk.
  // The crash window between mutation and the write completing is covered by
  // `resetSendingToQueued` on the next hydrate. Real stores (localStorage / the
  // AsyncStorage write queue) preserve order; Python's `_commit` awaits instead.
  function commit(next: OutboxEntry<T>[]): void {
    items = next
    if (cacheKey) void cache.setItem(cacheKey, JSON.stringify(items)).catch(() => {})
    for (const l of listeners) l()
  }

  return {
    get: () => items,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    async hydrate(key) {
      cacheKey = key
      let loaded: OutboxEntry<T>[] = []
      try {
        const raw = await cache.getItem(key)
        if (raw) {
          const parsed = JSON.parse(raw)
          if (Array.isArray(parsed)) loaded = parsed as OutboxEntry<T>[]
        }
      } catch {
        // corrupt blob → start empty; never brick on bad JSON
      }
      items = resetSendingToQueued(loaded)
      for (const l of listeners) l()
    },
    clear() {
      cacheKey = null
      items = []
      for (const l of listeners) l()
    },
    enqueue(id, item, ts) {
      if (items.some((i) => i.id === id)) return // dedup by id
      commit([...items, { id, item, status: "queued", attempts: 0, enqueuedAt: ts ?? Date.now() }])
    },
    claim(id) {
      const it = items.find((i) => i.id === id)
      if (!it || it.status === "sending") return false
      commit(items.map((i) => (i.id === id ? { ...i, status: "sending" } : i)))
      return true
    },
    remove(id) {
      commit(items.filter((i) => i.id !== id))
    },
    recordFailure(id, maxAttempts) {
      commit(
        items.map((i) => {
          if (i.id !== id) return i
          const attempts = i.attempts + 1
          return { ...i, attempts, status: attempts >= maxAttempts ? "failed" : "queued" }
        }),
      )
    },
    markFailed(id) {
      commit(items.map((i) => (i.id === id ? { ...i, status: "failed", attempts: i.attempts + 1 } : i)))
    },
    retry(id) {
      commit(items.map((i) => (i.id === id ? { ...i, status: "queued" } : i)))
    },
    pending(predicate) {
      return items.filter((i) => (predicate ? predicate(i.item) : true))
    },
  }
}
