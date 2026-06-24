/**
 * Regression tests for the stale-while-revalidate data-loss race.
 *
 * Bug: SyncManager.ingest() (called via mergeResult / onRevalidated) and
 * writeCache in revalidateLoop unconditionally overwrote localData/lastHash/
 * lastCheckpoint with no staleness guard. If the user pushed a new value while
 * a background revalidation was in-flight, the pre-push snapshot from the
 * revalidation clobbered the post-push state — silently losing the edit and
 * resetting lastHash to a stale value (causing a spurious 409 ConflictError on
 * the next push).
 *
 * Fix A: SyncManager.ingest() drops any result whose document timestamp is
 *        strictly less than the current lastCheckpoint.
 *
 * Fix B: StarfishClient tracks the latest timestamp written to each cache key
 *        via writeCache (synchronously, in-memory). revalidateLoop skips the
 *        write + onRevalidated callback when the server snapshot is older than
 *        the current tracked timestamp (meaning a push() wrote a newer value
 *        while the revalidation was in-flight).
 *
 * Important: Fix B only applies when push() and the revalidation loop share the
 * SAME StarfishClient instance. In practice SyncManager always uses a single
 * client instance for both operations, so this is the real-world case.
 */

import { describe, it, expect, vi, afterEach } from "vitest"
import type { PullResult } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import type { PullCache } from "../src/types.js"

afterEach(() => vi.useRealTimers())

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function memCache(): PullCache & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    async get(k) { return store.get(k) ?? null },
    async set(k, v) { store.set(k, v) },
  }
}

// ---------------------------------------------------------------------------
// Fix A: SyncManager.ingest() staleness guard
// ---------------------------------------------------------------------------

describe("SyncManager.ingest() staleness guard", () => {
  it("accepts an ingest result when no push has happened (lastCheckpoint = 0)", async () => {
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: vi.fn() as unknown as typeof fetch,
    })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })

    const fresh: PullResult = { data: { v: 1 }, hash: "h1", timestamp: 5, authorPubkey: undefined, authorSignature: undefined }
    await sync.ingest(fresh)

    expect(sync.getData()).toEqual({ v: 1 })
    expect(sync.getHash()).toBe("h1")
    expect(sync.getLastPullFromCache()).toBe(false)
  })

  it("drops a stale revalidation result that arrived after a push", async () => {
    const fetchMock = vi.fn()
      // Initial pull response (ts:10)
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 10 }))
      // Push response — server advances timestamp to 20
      .mockResolvedValueOnce(jsonResponse({ hash: "h2", timestamp: 20 }))

    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })

    // Establish state via pull (lastCheckpoint = 10)
    await sync.pull()
    expect(sync.getHash()).toBe("h1")

    // Push advances lastCheckpoint to 20
    await sync.push({ v: 2 })
    expect(sync.getHash()).toBe("h2")
    expect(sync.getData()).toEqual({ v: 2 })

    // Stale revalidation result (ts:10 < lastCheckpoint:20) — must be dropped
    const staleResult: PullResult = {
      data: { v: 1 }, // pre-push snapshot
      hash: "h1",
      timestamp: 10,
      authorPubkey: undefined,
      authorSignature: undefined,
    }
    await sync.ingest(staleResult)

    // State must NOT have been overwritten
    expect(sync.getData()).toEqual({ v: 2 })
    expect(sync.getHash()).toBe("h2")
  })

  it("accepts a revalidation result whose timestamp equals lastCheckpoint (same version, safe)", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 10 }))

    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })
    await sync.pull() // lastCheckpoint = 10

    // Same version as current checkpoint — safe to ingest (a re-confirm of same state)
    const sameVersionResult: PullResult = {
      data: { v: 1 },
      hash: "h1",
      timestamp: 10, // equals lastCheckpoint
      authorPubkey: undefined,
      authorSignature: undefined,
    }
    await sync.ingest(sameVersionResult)

    expect(sync.getData()).toEqual({ v: 1 })
    expect(sync.getHash()).toBe("h1")
    expect(sync.getLastPullFromCache()).toBe(false) // marked as live
  })

  it("accepts a revalidation result with a NEWER timestamp (server was updated)", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 5 }))

    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })
    await sync.pull() // lastCheckpoint = 5

    const newerResult: PullResult = {
      data: { v: 3 },
      hash: "h3",
      timestamp: 15, // newer than lastCheckpoint (5)
      authorPubkey: undefined,
      authorSignature: undefined,
    }
    await sync.ingest(newerResult)

    expect(sync.getData()).toEqual({ v: 3 })
    expect(sync.getHash()).toBe("h3")
  })
})

// ---------------------------------------------------------------------------
// Fix B: revalidateLoop cache staleness guard
//
// Note: Fix B only works when push() and the revalidation loop share the SAME
// StarfishClient instance (so latestCacheTimestamp is updated by the push).
// SyncManager always uses a single client for both, matching this design.
// ---------------------------------------------------------------------------

describe("staleWhileRevalidate cache staleness guard", () => {
  /**
   * Sequence:
   *  1. Initial pull → cache {v:1, h1, ts:5}
   *  2. SWR pull → serves cache, starts bg revalidation (held pending via mock)
   *  3. push() via SAME client → {h2, ts:20} → client.latestCacheTimestamp[key]=20
   *  4. bg revalidation resolves with stale {v:1, h1, ts:5}
   *     → ts:5 < latestTs:20 → must NOT overwrite cache or fire onRevalidated
   */
  it("revalidation result older than a concurrent push does not overwrite the cache", async () => {
    vi.useFakeTimers()
    const cache = memCache()

    let revalidationResolveFn: (r: Response) => void
    const revalidationPending = new Promise<Response>((res) => { revalidationResolveFn = res })

    const fetchMock = vi.fn()
      // (1) Initial live pull → ts:5
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 5 }))
      // (2) SWR background revalidation — held pending until step (4)
      .mockImplementationOnce(() => revalidationPending)
      // (3) Push — resolves immediately with ts:20
      .mockResolvedValueOnce(jsonResponse({ hash: "h2", timestamp: 20 }))

    const onRevalidated = vi.fn()
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      onRevalidated,
    })

    // (1) Prime the cache via a live pull — latestCacheTimestamp[key] = 5
    await client.pull("/pull/doc")

    // (2) SWR pull — returns cached result immediately; revalidateLoop starts
    // inside pull() (synchronously, before pull returns) and consumes mock #2
    const swr = await client.pull("/pull/doc", { staleWhileRevalidate: true })
    expect((swr as { hash: string }).hash).toBe("h1") // served stale

    // (3) Push via SAME client — consumes mock #3; writeCache updates
    // latestCacheTimestamp["/pull/doc"] = 20
    await client.push("/push/doc", { v: 2 }, "h1")

    // Confirm cache now holds the pushed snapshot (ts:20)
    const afterPush = await client.peekCache("/pull/doc")
    expect(afterPush?.hash).toBe("h2")
    expect(afterPush?.timestamp).toBe(20)

    // (4) Resolve the pending background revalidation with the pre-push snapshot (ts:5)
    // This arrives AFTER push advanced latestCacheTimestamp to 20.
    revalidationResolveFn!(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 5 }))
    // Advance timers by 0ms — flushes all pending microtasks and immediate timers
    await vi.advanceTimersByTimeAsync(0)

    // Cache must still hold the pushed snapshot — NOT overwritten by the stale result
    const afterRevalidation = await client.peekCache("/pull/doc")
    expect(afterRevalidation?.hash).toBe("h2")
    expect(afterRevalidation?.timestamp).toBe(20)

    // onRevalidated must NOT have been called — the stale result was dropped
    expect(onRevalidated).not.toHaveBeenCalled()
  })

  it("revalidation result with same timestamp as latest write is still applied", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()

    const freshData = { data: { v: 2 }, hash: "h2", timestamp: 10 }
    const fetchMock = vi.fn()
      // Initial pull → ts:5
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 5 }))
      // SWR background revalidation → ts:10 (newer)
      .mockResolvedValueOnce(jsonResponse(freshData))

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      onRevalidated,
    })

    await client.pull("/pull/doc")  // prime (ts:5, latestCacheTimestamp[key]=5)

    // SWR pull — revalidation starts immediately (mock #2 resolves instantly: ts:10)
    await client.pull("/pull/doc", { staleWhileRevalidate: true })

    // Advance timers by 0ms — flushes all pending microtasks and immediate timers
    await vi.advanceTimersByTimeAsync(0)

    // ts:10 >= latestTs:5 → fires normally
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    expect(onRevalidated).toHaveBeenCalledWith(
      expect.stringContaining("/pull/doc"),
      expect.objectContaining({ hash: "h2" }),
    )
    const peek = await client.peekCache("/pull/doc")
    expect(peek?.hash).toBe("h2")
  })

  it("first-ever revalidation (no prior write) is never dropped", async () => {
    // When latestCacheTimestamp has no entry (key never written via writeCache),
    // latestTs defaults to -1, so any revalidation result (ts >= 0) passes.
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()

    // Manually seed the cache (bypassing writeCache) so latestCacheTimestamp stays unset
    const cacheKey = "/pull/doc"
    cache.store.set(cacheKey, JSON.stringify({
      data: { v: 0 }, hash: "h0", timestamp: 5, cachedAt: Date.now(),
    }))

    const fetchMock = vi.fn()
      // SWR revalidation returns ts:10
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 10 }))

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      onRevalidated,
    })

    // SWR pull — reads from manually-seeded cache, starts revalidation
    await client.pull("/pull/doc", { staleWhileRevalidate: true })
    await vi.advanceTimersByTimeAsync(0)

    // latestTs = -1 (no prior writeCache), result.ts = 10 >= -1 → fires
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    expect(onRevalidated).toHaveBeenCalledWith(
      expect.stringContaining("/pull/doc"),
      expect.objectContaining({ hash: "h1" }),
    )
  })
})
