/**
 * Durable write-queue: dedup, persistence + crash-safe hydrate, single-shot claim,
 * drain success/failure with auto-retry-then-fail, predicate filtering.
 */
import { describe, it, expect, beforeEach } from "vitest"
import { createOutboxQueue, drainOutbox, type LocalCache, type OutboxEntry } from "../src/index.js"

function memCache(): LocalCache & { map: Map<string, string> } {
  const map = new Map<string, string>()
  return {
    map,
    getItem: async (k) => map.get(k) ?? null,
    setItem: async (k, v) => void map.set(k, v),
    removeItem: async (k) => void map.delete(k),
  }
}

interface Msg {
  room: string
  text: string
}

describe("outbox queue", () => {
  let cache: ReturnType<typeof memCache>
  beforeEach(() => {
    cache = memCache()
  })

  it("enqueues, dedups by id, and persists write-through", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r1", text: "hi" })
    q.enqueue("m1", { room: "r1", text: "dup" }) // ignored (same id)
    q.enqueue("m2", { room: "r2", text: "yo" })
    expect(q.get().map((e) => e.id)).toEqual(["m1", "m2"])
    const persisted = JSON.parse(cache.map.get("outbox.me")!) as OutboxEntry<Msg>[]
    expect(persisted).toHaveLength(2)
    expect(persisted[0]!.item.text).toBe("hi")
  })

  it("resets stuck 'sending' entries to 'queued' on hydrate", async () => {
    cache.map.set(
      "outbox.me",
      JSON.stringify([{ id: "m1", item: { room: "r", text: "x" }, status: "sending", attempts: 1, enqueuedAt: 1 }]),
    )
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    expect(q.get()[0]!.status).toBe("queued")
  })

  it("claim is single-shot (no double-send)", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r", text: "x" })
    expect(q.claim("m1")).toBe(true)
    expect(q.claim("m1")).toBe(false)
  })

  it("drain sends queued entries oldest-first and removes them on success", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r", text: "a" })
    q.enqueue("m2", { room: "r", text: "b" })
    const sentOrder: string[] = []
    const res = await drainOutbox(q, async (e) => void sentOrder.push(e.item.text))
    expect(sentOrder).toEqual(["a", "b"])
    expect(res).toEqual({ sent: 2, failed: 0 })
    expect(q.get()).toHaveLength(0)
  })

  it("auto-retries below maxAttempts, then escalates to failed", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r", text: "x" })
    const send = async () => {
      throw new Error("offline")
    }
    let r = await drainOutbox(q, send, { maxAttempts: 2 })
    expect(r).toEqual({ sent: 0, failed: 0 }) // attempt 1 → still queued
    expect(q.get()[0]!.status).toBe("queued")
    expect(q.get()[0]!.attempts).toBe(1)
    r = await drainOutbox(q, send, { maxAttempts: 2 })
    expect(r).toEqual({ sent: 0, failed: 1 }) // attempt 2 → failed
    expect(q.get()[0]!.status).toBe("failed")
  })

  it("skips failed entries until retry() re-queues them", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r", text: "x" })
    await drainOutbox(q, async () => { throw new Error("x") }, { maxAttempts: 1 })
    expect(q.get()[0]!.status).toBe("failed")
    // A failed entry is not drained again until manually retried.
    const r1 = await drainOutbox(q, async () => {})
    expect(r1.sent).toBe(0)
    q.retry("m1")
    const r2 = await drainOutbox(q, async () => {})
    expect(r2.sent).toBe(1)
  })

  it("filters pending entries by predicate", async () => {
    const q = createOutboxQueue<Msg>(cache)
    await q.hydrate("outbox.me")
    q.enqueue("m1", { room: "r1", text: "a" })
    q.enqueue("m2", { room: "r2", text: "b" })
    q.enqueue("m3", { room: "r1", text: "c" })
    expect(q.pending((m) => m.room === "r1").map((e) => e.id)).toEqual(["m1", "m3"])
  })
})
