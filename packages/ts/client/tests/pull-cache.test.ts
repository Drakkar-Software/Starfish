import { describe, it, expect, vi, afterEach } from "vitest"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient, pullWasFromCache } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { StarfishHttpError } from "../src/types.js"
import type { PullCache } from "../src/types.js"
import { createStarfishStore } from "../src/bindings/zustand.js"

// An in-memory PullCache that also exposes its backing map for assertions.
function memCache(): PullCache & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    async get(k) {
      return store.get(k) ?? null
    },
    async set(k, v) {
      store.set(k, v)
    },
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

// Reversible stub Encryptor (mirrors sync-encryptor.test.ts): wraps the payload
// under `_encrypted`, throws on a non-encrypted blob — so a decrypt of foreign
// data fails, exercising the "seed nothing on decrypt failure" path.
function stubEncryptor(): Encryptor {
  return {
    async encrypt(data) {
      return { _encrypted: JSON.stringify(data) }
    },
    async decrypt(wrapper) {
      const blob = (wrapper as Record<string, unknown>)._encrypted
      if (typeof blob !== "string") throw new Error("not encrypted")
      return JSON.parse(blob)
    },
  } as Encryptor
}

afterEach(() => vi.useRealTimers())

describe("StarfishClient read-through pull cache", () => {
  it("writes through on a successful pull and serves it when the transport is unreachable", async () => {
    const cache = memCache()
    let online = true
    const fetchMock = vi.fn(async () => {
      if (!online) throw new TypeError("Failed to fetch")
      return jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 })
    })
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })

    const live = await client.pull("/pull/doc")
    expect((live as { data: unknown }).data).toEqual({ k: "v" })
    expect(pullWasFromCache(live as never)).toBe(false)
    expect(cache.store.has("/pull/doc")).toBe(true)

    online = false
    const offline = await client.pull("/pull/doc")
    expect((offline as { data: unknown }).data).toEqual({ k: "v" })
    expect((offline as { hash: string }).hash).toBe("h1")
    expect(pullWasFromCache(offline as never)).toBe(true)
  })

  it("propagates an HTTP error (404) instead of serving cache — a real server answer", async () => {
    const cache = memCache()
    let mode: "ok" | "404" = "ok"
    const fetchMock = vi.fn(async () =>
      mode === "ok" ? jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 }) : jsonResponse("nope", 404),
    )
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })
    await client.pull("/pull/doc") // primes the cache
    mode = "404"
    await expect(client.pull("/pull/doc")).rejects.toBeInstanceOf(StarfishHttpError)
  })

  it("rethrows the transport error when there's no cached entry", async () => {
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: vi.fn(async () => {
        throw new TypeError("Failed to fetch")
      }) as unknown as typeof fetch,
      cache: memCache(),
    })
    await expect(client.pull("/pull/none")).rejects.toBeInstanceOf(TypeError)
  })

  it("treats an entry older than cacheMaxAgeMs as a miss", async () => {
    vi.useFakeTimers()
    vi.setSystemTime(0)
    let online = true
    const fetchMock = vi.fn(async () => {
      if (!online) throw new TypeError("Failed to fetch")
      return jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 })
    })
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache: memCache(),
      cacheMaxAgeMs: 1000,
    })
    await client.pull("/pull/doc") // cached at t=0
    online = false
    vi.setSystemTime(2000) // past the 1s TTL
    await expect(client.pull("/pull/doc")).rejects.toBeInstanceOf(TypeError)
  })

  it("does not cache append-collection pulls", async () => {
    const cache = memCache()
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: vi.fn(async () => jsonResponse({ data: { items: [1, 2] }, hash: "h", timestamp: 1 })) as unknown as typeof fetch,
      cache,
    })
    const items = await client.pull("/pull/log", { appendField: "items" })
    expect(items).toEqual([1, 2])
    expect(cache.store.size).toBe(0)
  })

  it("peekCache returns the cached snapshot without hitting the network", async () => {
    const cache = memCache()
    const fetchMock = vi.fn(async () => jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })
    await client.pull("/pull/doc")
    fetchMock.mockClear()
    const peek = await client.peekCache("/pull/doc")
    expect(peek?.data).toEqual({ k: "v" })
    expect(pullWasFromCache(peek!)).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe("stale-while-revalidate (cacheFallbackStatuses)", () => {
  function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
    return new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json", ...headers },
    })
  }

  it("serves cache on 429 and does not throw when a snapshot exists", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const liveData = { data: { k: "v" }, hash: "h1", timestamp: 5 }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(liveData))             // initial pull → caches
      .mockResolvedValue(jsonResponse("rate limited", 429))      // all subsequent → 429
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
    })
    await client.pull("/pull/doc") // primes the cache

    const result = await client.pull("/pull/doc")
    expect(pullWasFromCache(result as never)).toBe(true)
    expect((result as { data: unknown }).data).toEqual({ k: "v" })
    vi.useRealTimers()
  })

  it("serves cache on 503 (5xx falls back the same way)", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { x: 1 }, hash: "h", timestamp: 1 }))
      .mockResolvedValue(jsonResponse("unavailable", 503))
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
    })
    await client.pull("/pull/doc")
    const result = await client.pull("/pull/doc")
    expect(pullWasFromCache(result as never)).toBe(true)
    vi.useRealTimers()
  })

  it("still throws on 404 even when it is not in cacheFallbackStatuses", async () => {
    const cache = memCache()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 }))
      .mockResolvedValue(jsonResponse("not found", 404))
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
    })
    await client.pull("/pull/doc") // primes the cache
    await expect(client.pull("/pull/doc")).rejects.toBeInstanceOf(StarfishHttpError)
  })

  it("throws on 429 when no snapshot is cached (nothing to serve)", async () => {
    const cache = memCache()
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse("rate limited", 429))
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
    })
    await expect(client.pull("/pull/doc")).rejects.toBeInstanceOf(StarfishHttpError)
  })

  it("background revalidation succeeds: updates cache and calls onRevalidated", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const freshData = { data: { updated: true }, hash: "h2", timestamp: 10 }
    const onRevalidated = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { stale: true }, hash: "h1", timestamp: 5 }))
      .mockResolvedValueOnce(jsonResponse("rate limited", 429))   // triggers SWR
      .mockResolvedValueOnce(jsonResponse(freshData))              // background success

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
      onRevalidated,
    })

    await client.pull("/pull/doc")                        // prime cache
    await client.pull("/pull/doc")                        // 429 → stale, schedules revalidation
    await vi.advanceTimersByTimeAsync(1100)               // initial delay = 1s

    expect(onRevalidated).toHaveBeenCalledTimes(1)
    expect(onRevalidated).toHaveBeenCalledWith(
      expect.stringContaining("/pull/doc"),
      expect.objectContaining({ hash: "h2" }),
    )
    // Cache should hold the fresh snapshot now
    const peek = await client.peekCache("/pull/doc")
    expect((peek as { hash: string }).hash).toBe("h2")
    vi.useRealTimers()
  })

  it("background revalidation honors Retry-After header", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }))
      .mockResolvedValueOnce(
        jsonResponse("limited", 429, { "Retry-After": "5" }),     // wait 5s
      )
      .mockResolvedValueOnce(jsonResponse({ data: { v: 2 }, hash: "h2", timestamp: 2 }))

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429],
      onRevalidated,
    })

    await client.pull("/pull/doc")
    await client.pull("/pull/doc")              // 429 → schedules revalidation with delay=5s

    await vi.advanceTimersByTimeAsync(4900)
    expect(onRevalidated).not.toHaveBeenCalled() // not yet

    await vi.advanceTimersByTimeAsync(200)
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    vi.useRealTimers()
  })

  it("concurrent 429 pulls on the same doc spawn only one revalidation loop", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()
    const freshData = { data: { v: 2 }, hash: "h2", timestamp: 2 }

    // prime → 429 × 2 (concurrent SWR pulls) → success (background revalidation)
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }))
      .mockResolvedValueOnce(jsonResponse("rate limited", 429))
      .mockResolvedValueOnce(jsonResponse("rate limited", 429))
      .mockResolvedValue(jsonResponse(freshData))  // first background attempt succeeds

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429],
      onRevalidated,
    })

    await client.pull("/pull/doc")  // prime cache
    // Two concurrent 429s — both serve from cache, but only ONE loop should start
    await Promise.all([client.pull("/pull/doc"), client.pull("/pull/doc")])

    // Advance past the 1s initial revalidation delay
    await vi.advanceTimersByTimeAsync(1100)

    // onRevalidated fires exactly once (one loop, one success)
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    // Total fetches: 1 prime + 2 SWR + 1 background = 4, not 5 (which would mean 2 loops)
    expect(fetchMock.mock.calls.length).toBe(4)
    vi.useRealTimers()
  })

  it("revalidation stops early when the server returns a non-fallback status (e.g. 403)", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }))
      .mockResolvedValueOnce(jsonResponse("limited", 429))  // triggers SWR
      .mockResolvedValueOnce(jsonResponse("forbidden", 403)) // background: genuine answer → stop

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500],
      onRevalidated,
    })

    await client.pull("/pull/doc")
    await client.pull("/pull/doc")
    await vi.advanceTimersByTimeAsync(2000)

    // onRevalidated never fires (server said 403 = genuine denial)
    expect(onRevalidated).not.toHaveBeenCalled()
    // Only 3 fetch calls: prime + 429 + one background attempt that got 403
    expect(fetchMock.mock.calls.length).toBe(3)
    vi.useRealTimers()
  })

  it("does not affect 404 behavior when cacheFallbackStatuses is not set", async () => {
    const cache = memCache()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { k: "v" }, hash: "h1", timestamp: 5 }))
      .mockResolvedValue(jsonResponse("not found", 404))
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      // no cacheFallbackStatuses — default behavior
    })
    await client.pull("/pull/doc")
    await expect(client.pull("/pull/doc")).rejects.toBeInstanceOf(StarfishHttpError)
  })
})

describe("SyncManager cache-first seeding", () => {
  it("seedFromCache decrypts the cached ciphertext in memory and flags fromCache", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    const sealed = await enc.encrypt({ name: "alice" })
    cache.store.set("/pull/t", JSON.stringify({ data: sealed, hash: "h", timestamp: 1, cachedAt: Date.now() }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache })
    const sync = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t", encryptor: enc })

    expect(await sync.seedFromCache()).toBe(true)
    expect(sync.getData()).toEqual({ name: "alice" })
    expect(sync.getHash()).toBe("h")
    expect(sync.getLastPullFromCache()).toBe(true)
  })

  it("seedFromCache returns false on a miss", async () => {
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache: memCache() })
    const sync = new SyncManager({ client, pullPath: "/pull/missing", pushPath: "/push/missing" })
    expect(await sync.seedFromCache()).toBe(false)
  })

  it("seedFromCache returns false when the cached blob can't be decrypted", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    cache.store.set("/pull/bad", JSON.stringify({ data: { not: "encrypted" }, hash: "h", timestamp: 1, cachedAt: Date.now() }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache })
    const sync = new SyncManager({ client, pullPath: "/pull/bad", pushPath: "/push/bad", encryptor: enc })
    expect(await sync.seedFromCache()).toBe(false)
    expect(sync.getData()).toEqual({})
  })

  it("pull() flags lastFromCache when the client served from cache (offline)", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    const sealed = await enc.encrypt({ name: "bob" })
    cache.store.set("/pull/t2", JSON.stringify({ data: sealed, hash: "h2", timestamp: 9, cachedAt: Date.now() }))
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: vi.fn(async () => {
        throw new TypeError("offline")
      }) as unknown as typeof fetch,
      cache,
    })
    const sync = new SyncManager({ client, pullPath: "/pull/t2", pushPath: "/push/t2", encryptor: enc })
    const r = await sync.pull()
    expect(r.data).toEqual({ name: "bob" })
    expect(sync.getLastPullFromCache()).toBe(true)
  })
})

describe("zustand store cache-first paint", () => {
  it("seed() populates data and sets stale=true from the offline cache", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    const sealed = await enc.encrypt({ messages: [{ id: "m1" }] })
    cache.store.set("/pull/room", JSON.stringify({ data: sealed, hash: "h", timestamp: 1, cachedAt: Date.now() }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache })
    const syncManager = new SyncManager({ client, pullPath: "/pull/room", pushPath: "/push/room", encryptor: enc })
    const store = createStarfishStore({ name: "room", syncManager, storage: false })

    expect(store.getState().stale).toBe(false)
    await store.getState().seed()
    expect(store.getState().stale).toBe(true)
    expect(store.getState().data).toEqual({ messages: [{ id: "m1" }] })
  })
})
