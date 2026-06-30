/**
 * Tests for readSpaces / pullSpacesDoc cache behaviour.
 *
 * Verifies that pullSpacesDoc opts into staleWhileRevalidate so readSpaces
 * returns the cached _spaces doc instantly (when a cache is configured) and
 * that it still swallows 404 on a miss.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest"

afterEach(() => vi.useRealTimers())
import { StarfishClient, StarfishHttpError, ConflictError } from "@drakkar.software/starfish-client"
import type { PullCache } from "@drakkar.software/starfish-client"
import { readSpaces, addSpaceMember, removeSpaceMember } from "../src/registry.js"
import { defaultSpaceLayout } from "../src/layout.js"
import type { Session } from "../src/session.js"
import { clearDocCache } from "../src/doc-cache.js"

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

const SPACE = "sp1"
const OWNER = "owner1"
const MEMBER = "member1"
const NEW_MEMBER = "member2"
const ACCESS_PULL = defaultSpaceLayout.spaceAccessPull(SPACE)
const ACCESS_PUSH = defaultSpaceLayout.spaceAccessPush(SPACE)

function makeAccessClient(opts: {
  pull?: () => Promise<{ data: unknown; hash: string } | null>
  push?: () => Promise<{ hash: string; timestamp: number }>
  peek?: () => Promise<{ data: unknown; hash: string } | null>
}): { client: unknown; pullSpy: ReturnType<typeof vi.fn>; pushSpy: ReturnType<typeof vi.fn>; peekSpy: ReturnType<typeof vi.fn> } {
  const pullSpy = vi.fn(opts.pull ?? (async () => ({
    data: { v: 1, owner: OWNER, members: [MEMBER] }, hash: "H_good",
  })))
  const pushSpy = vi.fn(opts.push ?? (async () => ({ hash: "H_new", timestamp: 1 })))
  const peekSpy = vi.fn(opts.peek ?? (async () => null))
  return {
    client: { pull: pullSpy, push: pushSpy, peekCache: peekSpy },
    pullSpy, pushSpy, peekSpy,
  }
}

function makeAccessSession(): Pick<Session, "userId" | "layout"> {
  return { userId: OWNER, layout: defaultSpaceLayout }
}

beforeEach(() => clearDocCache())

describe("addSpaceMember / updateSpaceAccess — peekCache seed + runCas retry", () => {
  it("A1: degraded pull (hash:'') + peekCache hit → push uses the good cached hash", async () => {
    const { client, pushSpy, peekSpy } = makeAccessClient({
      pull: async () => ({ data: {}, hash: "" }),         // degraded server read
      peek: async () => ({ data: { v: 1, owner: OWNER, members: [MEMBER] }, hash: "H_cached" }),
    })
    await addSpaceMember(client as never, SPACE, OWNER, NEW_MEMBER, makeAccessSession() as Session)

    expect(peekSpy).toHaveBeenCalledWith(ACCESS_PULL)
    expect(pushSpy).toHaveBeenCalledTimes(1)
    const [, payload, baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_cached")            // good cached hash, not ""
    expect((payload as { members: string[] }).members).toContain(NEW_MEMBER)
  })

  it("A2: 409 on first push → runCas retries with currentHash and succeeds", async () => {
    let attempt = 0
    const { client, pushSpy } = makeAccessClient({
      pull: async () => ({ data: { v: 1, owner: OWNER, members: [MEMBER] }, hash: "H_good" }),
      push: async () => {
        if (++attempt === 1) throw new ConflictError("H_conflict")
        return { hash: "H_new", timestamp: 1 }
      },
    })
    // Should not throw — runCas absorbs the first 409 and retries.
    await expect(addSpaceMember(client as never, SPACE, OWNER, NEW_MEMBER, makeAccessSession() as Session)).resolves.toBeUndefined()
    expect(pushSpy).toHaveBeenCalledTimes(2)
  })

  it("A3: member already present → mutator returns null → no push", async () => {
    const { client, pushSpy } = makeAccessClient({
      pull: async () => ({ data: { v: 1, owner: OWNER, members: [MEMBER, NEW_MEMBER] }, hash: "H_good" }),
    })
    await addSpaceMember(client as never, SPACE, OWNER, NEW_MEMBER, makeAccessSession() as Session)
    expect(pushSpy).not.toHaveBeenCalled()
  })

  it("A4: removeSpaceMember with degraded pull + peekCache hit → push uses cached hash", async () => {
    const { client, pushSpy, peekSpy } = makeAccessClient({
      pull: async () => ({ data: {}, hash: "" }),
      peek: async () => ({ data: { v: 1, owner: OWNER, members: [MEMBER] }, hash: "H_cached" }),
    })
    await removeSpaceMember(client as never, SPACE, MEMBER, makeAccessSession() as Session)

    expect(peekSpy).toHaveBeenCalled()
    expect(pushSpy).toHaveBeenCalledTimes(1)
    const [, payload, baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H_cached")
    expect((payload as { members: string[] }).members).not.toContain(MEMBER)
  })
})

describe("readSpaces staleWhileRevalidate", () => {
  it("returns the cached _spaces doc immediately and fires background revalidation", async () => {
    vi.useFakeTimers()
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

    // The background revalidation fires immediately (no delay) and updates cache.
    // advanceTimersByTimeAsync(0) flushes all pending microtasks and zero-delay timers,
    // ensuring the revalidation Promise chain fully settles before we assert.
    await vi.advanceTimersByTimeAsync(0)
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
