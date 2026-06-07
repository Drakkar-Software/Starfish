/**
 * `@drakkar.software/starfish-outbox` — a durable, per-identity offline
 * **write-queue** (the client-side complement to the server-side `queuing`
 * extension).
 *
 * Generic over the queued item `<T>`: the caller
 * owns what an item is, supplies its dedup `id`, and a `send` that performs the
 * real write. The queue handles persistence (write-through to a `LocalCache`),
 * dedup-by-id, single-shot claim (no double-send), attempt counting with
 * auto-retry-then-fail, crash-safe `sending` recovery, and subscriptions. The
 * {@link drainOutbox} driver is connectivity-agnostic — the caller triggers it on
 * whatever reconnect signal it has.
 */

export { createOutboxQueue, resetSendingToQueued } from "./queue.js"
export type { OutboxQueue, OutboxEntry, OutboxStatus, LocalCache } from "./queue.js"

export { drainOutbox } from "./drain.js"
export type { DrainOptions, DrainResult } from "./drain.js"
