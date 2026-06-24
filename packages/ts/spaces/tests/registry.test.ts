/**
 * Tests for readSpaces / pullSpacesDoc cache behaviour.
 *
 * Verifies that pullSpacesDoc opts into staleWhileRevalidate so readSpaces
 * returns the cached _spaces doc instantly (when a cache is configured) and
 * that it still swallows 404 on a miss.
 */
import { describe, it, expect, vi } from "vitest"
import { StarfishClient, StarfishHttpError } from "@drakkar.software/starfish-client"
import type { PullCache } from "@drakkar.software/starfish-client"
import { readSpaces } from "../src/registry.js"
import { defaultSpaceLayout } from "../src/layout.js"
import type { Session } from "../src/session.js"

// ── Helpers ────────────────────────────────────────────────────────────────────

function memCache(): PullCache & { store: Map<string, string> } {
  const store = new Map<string, string>()
  return {
    store,
    async get(k) { return store.get(k) ?? null },
    async set(k, v) { store.set(k, v) },
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function makeSession(userId = "u1"): Pick<Session, "userId" | "layout"> {
  return { userId, layout: defaultSpaceLayout }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

describe("readSpaces staleWhileRevalidate", () => {
  it("returns the cached _spaces doc immediately and fires background revalidation", async () => {
    const cache = memCache()
    const spacesPath = defaultSpaceLayout.spacesPull("u1")  // /pull/user/u1/_spaces
    const stalePayload = { spaces: [{ id: "s1" }], caps: {}, pubAccess: {} }
    const freshPayload = { spaces: [{ id: "s1" }, { id: "s2" }], caps: {}, pubAccess: {} }
    cache.store.set(spacesPath, JSON.stringify({
      data: stalePayload,
      hash: "hcached",
      timestamp: 5,
      cachedAt: Date.now(),
    }))

    const onRevalidated = vi.fn()
    // Background revalidation will call fetch — set it up to return fresh data
    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ data: freshPayload, hash: "hfresh", timestamp: 10 }),
    )
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
      onRevalidated,
    })

    // readSpaces returns the STALE cached value immediately
    const doc = await readSpaces(client, makeSession() as Session)
    expect(doc.spaces).toEqual([{ id: "s1" }])
    expect(doc.hash).toBe("hcached")

    // The background revalidation fires immediately (no delay) and updates cache
    // Give microtasks a chance to flush
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    expect(fetchMock).toHaveBeenCalledTimes(1)  // background revalidation fetch
    expect(onRevalidated).toHaveBeenCalledTimes(1)
    expect(onRevalidated).toHaveBeenCalledWith(
      expect.stringContaining("_spaces"),
      expect.objectContaining({ hash: "hfresh" }),
    )
  })

  it("falls through to network when the cache is empty (first boot)", async () => {
    const cache = memCache()
    const livePayload = { data: { spaces: [{ id: "s2" }], caps: {}, pubAccess: {} }, hash: "hlive", timestamp: 10 }
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(livePayload))

    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
    })

    const doc = await readSpaces(client, makeSession() as Session)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(doc.spaces).toEqual([{ id: "s2" }])
    expect(doc.hash).toBe("hlive")
  })

  it("returns an empty SpacesDoc on 404 (new user, no _spaces doc yet)", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse("not found", 404))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })

    const doc = await readSpaces(client, makeSession() as Session)
    expect(doc.spaces).toEqual([])
    expect(doc.caps).toEqual({})
    expect(doc.hash).toBeNull()
  })

  it("returns an empty SpacesDoc on any other error (defensive fallback in readSpaces)", async () => {
    const fetchMock = vi.fn().mockRejectedValueOnce(new TypeError("network failure"))
    const client = new StarfishClient({ baseUrl: "https://h", fetch: fetchMock as unknown as typeof fetch })

    const doc = await readSpaces(client, makeSession() as Session)
    expect(doc.spaces).toEqual([])
  })
})
