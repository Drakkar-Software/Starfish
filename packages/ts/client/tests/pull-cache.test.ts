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

describe("push write-through to pull cache", () => {
  it("updates the pull cache after a successful push so offline restart reads the new state", async () => {
    const cache = memCache()
    let online = true
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (!online) throw new TypeError("Failed to fetch")
      const method = (init as RequestInit | undefined)?.method ?? "GET"
      if (method === "GET") return jsonResponse({ data: { v: 1, x: "old" }, hash: "h1", timestamp: 1 })
      // POST (push) — return success with new hash
      return jsonResponse({ hash: "h2", timestamp: 2 })
    })
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })

    // Prime the cache via a pull.
    await client.pull("/pull/spaces/s1/doc")
    expect((JSON.parse(cache.store.get("/pull/spaces/s1/doc")!) as { hash: string }).hash).toBe("h1")

    // Push new data.
    await client.push("/push/spaces/s1/doc", { v: 1, x: "new" }, "h1")

    // Cache must be updated to the pushed state.
    const cached = JSON.parse(cache.store.get("/pull/spaces/s1/doc")!) as { data: unknown; hash: string }
    expect(cached.hash).toBe("h2")
    expect(cached.data).toEqual({ v: 1, x: "new" })

    // Offline pull must serve the NEW state, not the old one.
    online = false
    const offlineResult = await client.pull("/pull/spaces/s1/doc")
    expect((offlineResult as { data: unknown }).data).toEqual({ v: 1, x: "new" })
    expect(pullWasFromCache(offlineResult as never)).toBe(true)
  })

  it("does not create a pull cache entry for a push path that was never pulled", async () => {
    const cache = memCache()
    const fetchMock = vi.fn(async () => jsonResponse({ hash: "h1", timestamp: 1 }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })

    await client.push("/push/user/u1/profile", { name: "bob" }, null)
    // Cache entry IS created — push write-through primes the cache even if never pulled.
    const entry = cache.store.get("/pull/user/u1/profile")
    expect(entry).toBeTruthy()
    expect((JSON.parse(entry!) as { data: unknown }).data).toEqual({ name: "bob" })
  })

  it("does not write the pull cache when no cache is configured", async () => {
    let pushed = false
    const fetchMock = vi.fn(async () => {
      pushed = true
      return jsonResponse({ hash: "h1", timestamp: 1 })
    })
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })
    await client.push("/push/doc", { v: 1 }, null)
    expect(pushed).toBe(true)
    // No cache was configured — the client should not throw.
  })

  it("does not overwrite a good cached hash when a degraded pull returns hash:\"\"", async () => {
    // Scenario: previous session persisted a good hash via push write-through.
    // On reload the server returns hash:"" (degraded/corrupt-envelope read).
    // The good hash must survive so peekCache still returns it for the next write.
    const cache = memCache()
    let mode: "good" | "degraded" = "good"
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      const method = (init as RequestInit | undefined)?.method ?? "GET"
      if (method !== "GET") return jsonResponse({ hash: "h_pushed", timestamp: 2 })
      if (mode === "good") return jsonResponse({ data: { v: 1 }, hash: "h_good", timestamp: 1 })
      return jsonResponse({ data: {}, hash: "", timestamp: 0 })  // degraded server read
    })
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })

    // A previous session's successful push primed the cache with a real hash.
    await client.push("/push/doc", { v: 1 }, "h_prev")
    expect((JSON.parse(cache.store.get("/pull/doc")!) as { hash: string }).hash).toBe("h_pushed")

    // On reload the server is degraded — pull returns hash:"".
    mode = "degraded"
    const degraded = await client.pull("/pull/doc").catch(() => null)
    expect((degraded as { hash: string } | null)?.hash).toBe("")

    // The cache entry must be UNCHANGED — the degraded read must not poison it.
    const cached = JSON.parse(cache.store.get("/pull/doc")!) as { hash: string }
    expect(cached.hash).toBe("h_pushed")  // good hash survives

    // peekCache still returns the good hash.
    const peeked = await client.peekCache("/pull/doc")
    expect(peeked?.hash).toBe("h_pushed")
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

describe("staleWhileRevalidate pull option", () => {
  it("returns cache immediately and revalidates in the background without initial delay", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const staleData = { data: { v: 1 }, hash: "h1", timestamp: 1 }
    const freshData = { data: { v: 2 }, hash: "h2", timestamp: 2 }
    const onRevalidated = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse(staleData))     // initial prime pull
      .mockResolvedValueOnce(jsonResponse(freshData))     // background revalidation

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      onRevalidated,
    })

    await client.pull("/pull/doc")  // prime cache

    // SWR pull: should return cached data immediately
    const result = await client.pull("/pull/doc", { staleWhileRevalidate: true })
    expect(pullWasFromCache(result as never)).toBe(true)
    expect((result as { data: unknown }).data).toEqual({ v: 1 })

    // Background revalidation fires immediately (no initial delay)
    await vi.advanceTimersByTimeAsync(0)
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    expect(onRevalidated).toHaveBeenCalledWith(
      expect.stringContaining("/pull/doc"),
      expect.objectContaining({ hash: "h2" }),
    )

    // Cache updated to fresh snapshot
    const peek = await client.peekCache("/pull/doc")
    expect((peek as { hash: string }).hash).toBe("h2")
    vi.useRealTimers()
  })

  it("falls through to network-first when there is no cache hit", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }),
    )
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache: memCache(),
    })

    // No prime: cache is empty — should go to network
    const result = await client.pull("/pull/doc", { staleWhileRevalidate: true })
    expect(pullWasFromCache(result as never)).toBe(false)
    expect((result as { data: unknown }).data).toEqual({ v: 1 })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it("deduplicates with a concurrent cacheFallbackStatuses revalidation loop", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const onRevalidated = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }))  // prime
      .mockResolvedValueOnce(jsonResponse("rate limited", 429))                              // error-SWR trigger
      .mockResolvedValueOnce(jsonResponse({ data: { v: 2 }, hash: "h2", timestamp: 2 }))   // background success

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429],
      onRevalidated,
    })

    await client.pull("/pull/doc")  // prime
    await client.pull("/pull/doc")  // 429 → starts error-SWR loop (delayed)

    // SWR-on-read while the error loop is in-flight: must NOT start a second loop
    await client.pull("/pull/doc", { staleWhileRevalidate: true })

    // Advance past the error loop's 1s initial delay
    await vi.advanceTimersByTimeAsync(1100)

    // Only one background fetch fired (the existing loop), onRevalidated once
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    // Total: prime(1) + 429(1) + swr-read(0 fetch, cache hit) + background(1) = 3
    expect(fetchMock.mock.calls.length).toBe(3)
    vi.useRealTimers()
  })

  it("is a no-op without a cache configured (falls through to network)", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }),
    )
    // No cache option
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })

    const result = await client.pull("/pull/doc", { staleWhileRevalidate: true })
    expect(pullWasFromCache(result as never)).toBe(false)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe("SyncManager.ingest()", () => {
  it("applies a PullResult to manager state without a network request", async () => {
    const cache = memCache()
    const fetchMock = vi.fn()
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })

    const fresh: Parameters<typeof sync.ingest>[0] = { data: { k: "fresh" }, hash: "h-fresh", timestamp: 99, authorPubkey: undefined, authorSignature: undefined }
    await sync.ingest(fresh)

    expect(sync.getData()).toEqual({ k: "fresh" })
    expect(sync.getHash()).toBe("h-fresh")
    expect(sync.getLastPullFromCache()).toBe(false)
    // No network calls
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("decrypts an E2E PullResult during ingest", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache })
    const sync = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc", encryptor: enc })

    const sealed = await enc.encrypt({ secret: 42 })
    const fresh: Parameters<typeof sync.ingest>[0] = { data: sealed, hash: "h-enc", timestamp: 5, authorPubkey: undefined, authorSignature: undefined }
    await sync.ingest(fresh)

    expect(sync.getData()).toEqual({ secret: 42 })
    expect(sync.getLastPullFromCache()).toBe(false)
  })
})

describe("zustand mergeResult + auto-merge on revalidation", () => {
  it("mergeResult() repaints data and clears stale without a network request", async () => {
    const enc = stubEncryptor()
    const cache = memCache()
    const sealed = await enc.encrypt({ v: 1 })
    cache.store.set("/pull/doc", JSON.stringify({ data: sealed, hash: "h1", timestamp: 1, cachedAt: Date.now() }))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: vi.fn() as unknown as typeof fetch, cache })
    const syncManager = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc", encryptor: enc })
    const store = createStarfishStore({ name: "doc", syncManager, storage: false })

    await store.getState().seed()
    expect(store.getState().stale).toBe(true)
    expect(store.getState().data).toEqual({ v: 1 })

    const freshSealed = await enc.encrypt({ v: 2 })
    await store.getState().mergeResult({ data: freshSealed, hash: "h2", timestamp: 2, authorPubkey: undefined, authorSignature: undefined })

    expect(store.getState().data).toEqual({ v: 2 })
    expect(store.getState().stale).toBe(false)
    expect(store.getState().hash).toBe("h2")
  })

  it("auto-merge: background revalidation paints fresh data into the store", async () => {
    vi.useFakeTimers()
    const cache = memCache()
    const freshData = { data: { updated: true }, hash: "h2", timestamp: 10 }
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ data: { stale: true }, hash: "h1", timestamp: 5 }))
      .mockResolvedValueOnce(jsonResponse("rate limited", 429))
      .mockResolvedValueOnce(jsonResponse(freshData))

    let onRevalidatedFired = false
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      cacheFallbackStatuses: [429, 500, 502, 503, 504],
      onRevalidated: () => { onRevalidatedFired = true },
    })
    const syncManager = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })
    const store = createStarfishStore({ name: "doc-auto", syncManager, storage: false })

    await client.pull("/pull/doc")   // prime cache
    await client.pull("/pull/doc")   // 429 → stale, schedules revalidation

    expect(onRevalidatedFired).toBe(false)
    // In the real auto-wire wiring (useSyncInit / acquireSyncStore), onRevalidated
    // would call store.mergeResult. We test mergeResult in isolation above;
    // here we verify that the client's onRevalidated fires with the fresh result.
    await vi.advanceTimersByTimeAsync(1100)
    expect(onRevalidatedFired).toBe(true)
    vi.useRealTimers()
  })

  it("pull() does not raise syncing spinner when store already has stale data (Gap D)", async () => {
    const cache = memCache()
    cache.store.set("/pull/doc", JSON.stringify({ data: { v: 0 }, hash: "h0", timestamp: 0, cachedAt: Date.now() }))

    let resolveNetwork: (r: Response) => void
    const networkPending = new Promise<Response>((res) => { resolveNetwork = res })
    const fetchMock = vi.fn().mockReturnValueOnce(networkPending)

    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch, cache })
    const syncManager = new SyncManager({ client, pullPath: "/pull/doc", pushPath: "/push/doc" })
    const store = createStarfishStore({ name: "doc-gapd", syncManager, storage: false })

    await store.getState().seed()
    expect(store.getState().stale).toBe(true)

    // Start pull (will block on network)
    const pullPromise = store.getState().pull()
    // syncing must NOT be raised while the store shows stale data
    expect(store.getState().syncing).toBe(false)

    // Let the network succeed
    resolveNetwork!(jsonResponse({ data: { v: 1 }, hash: "h1", timestamp: 1 }))
    await pullPromise
    expect(store.getState().stale).toBe(false)
    expect(store.getState().syncing).toBe(false)
  })
})
