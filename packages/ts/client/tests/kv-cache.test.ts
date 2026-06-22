/**
 * Tests for createKvPullCache — KV-backed PullCache adapter.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import { createKvPullCache } from "../src/kv-cache.js"
import type { KvStore } from "../src/kv-cache.js"

/** Simple in-memory KV store for testing. */
function memKv(): KvStore & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    getItem: async (k) => store.get(k) ?? null,
    setItem: async (k, v) => { store.set(k, v) },
    removeItem: async (k) => { store.delete(k) },
  }
}

describe("createKvPullCache", () => {
  it("returns null for a missing key", async () => {
    const cache = createKvPullCache(memKv())
    expect(await cache.get("does-not-exist")).toBeNull()
  })

  it("stores and retrieves a value round-trip", async () => {
    const cache = createKvPullCache(memKv())
    const payload = JSON.stringify({ data: { x: 1 }, hash: "h1", timestamp: 100 })
    await cache.set("/pull/doc", payload)
    expect(await cache.get("/pull/doc")).toBe(payload)
  })

  it("uses the configured prefix so keys are namespaced", async () => {
    const kv = memKv()
    const cache = createKvPullCache(kv, { prefix: "myapp:" })
    await cache.set("/pull/doc", "val")
    expect(kv.store.has("myapp:/pull/doc")).toBe(true)
    expect(kv.store.has("starfish.pullcache./pull/doc")).toBe(false)
  })

  it("returns null for an expired entry when maxAgeMs is set", async () => {
    vi.useFakeTimers()
    const kv = memKv()
    const cache = createKvPullCache(kv, { maxAgeMs: 1_000 })

    await cache.set("/pull/doc", "fresh")
    expect(await cache.get("/pull/doc")).toBe("fresh")

    // Advance time past the TTL.
    vi.advanceTimersByTime(1_001)
    expect(await cache.get("/pull/doc")).toBeNull()

    vi.useRealTimers()
  })

  it("returns a value that has NOT expired yet", async () => {
    vi.useFakeTimers()
    const kv = memKv()
    const cache = createKvPullCache(kv, { maxAgeMs: 5_000 })

    await cache.set("/pull/doc", "payload")
    vi.advanceTimersByTime(4_999)
    expect(await cache.get("/pull/doc")).toBe("payload")

    vi.useRealTimers()
  })

  it("does not expire entries when maxAgeMs is not set", async () => {
    vi.useFakeTimers()
    const kv = memKv()
    const cache = createKvPullCache(kv) // no maxAgeMs

    await cache.set("/pull/doc", "ageless")
    vi.advanceTimersByTime(365 * 24 * 60 * 60 * 1_000) // one year
    expect(await cache.get("/pull/doc")).toBe("ageless")

    vi.useRealTimers()
  })

  it("is backward-compatible with plain-string entries (no envelope)", async () => {
    // Pre-existing entries stored as raw strings (before createKvPullCache was used)
    // should still be readable.
    const kv = memKv()
    kv.store.set("starfish.pullcache./pull/legacy", '"legacy-value"')

    const cache = createKvPullCache(kv)
    expect(await cache.get("/pull/legacy")).toBe('"legacy-value"')
  })

  it("swallows getItem errors (never throws)", async () => {
    const brokenKv: KvStore = {
      getItem: async () => { throw new Error("storage unavailable") },
      setItem: async () => { throw new Error("storage unavailable") },
    }
    const cache = createKvPullCache(brokenKv)
    await expect(cache.get("key")).resolves.toBeNull()
    await expect(cache.set("key", "val")).resolves.toBeUndefined()
  })

  it("swallows setItem errors (never throws)", async () => {
    const kv: KvStore = {
      getItem: async () => null,
      setItem: async () => { throw new Error("disk full") },
    }
    const cache = createKvPullCache(kv)
    await expect(cache.set("key", "val")).resolves.toBeUndefined()
  })

  it("isolates keys across different prefixes", async () => {
    const kv = memKv()
    const cache1 = createKvPullCache(kv, { prefix: "ns1:" })
    const cache2 = createKvPullCache(kv, { prefix: "ns2:" })

    await cache1.set("/pull/doc", "from-ns1")
    await cache2.set("/pull/doc", "from-ns2")

    expect(await cache1.get("/pull/doc")).toBe("from-ns1")
    expect(await cache2.get("/pull/doc")).toBe("from-ns2")
  })
})
