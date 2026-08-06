/**
 * Tests for readSpaces / pullSpacesDoc cache behaviour.
 *
 * pullSpacesDoc is deliberately network-first (NOT staleWhileRevalidate) — see
 * the rationale comment on pullSpacesDoc in ../src/registry.ts. StarfishClient's
 * push() write-through to the pull cache is fire-and-forget (unawaited), so an
 * SWR-enabled read shortly after a write (e.g. readSpaces() right after
 * createSpace()) could race that write-through and serve the pre-write
 * snapshot — observed in production via findOrCreateMirrorSpace creating a
 * space then re-reading it in the same session. Verifies readSpaces always
 * hits the network (ignoring any pre-populated cache) and still swallows 404
 * on a miss.
 */
import { describe, it, expect, vi, afterEach, beforeEach } from "vitest"

afterEach(() => vi.useRealTimers())
import { StarfishClient, StarfishHttpError, ConflictError } from "@drakkar.software/starfish-client"
import type { PullCache } from "@drakkar.software/starfish-client"
import { readSpaces, addSpaceMember, removeSpaceMember, writeSpaces, updateSpacesDoc } from "../src/registry.js"
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

// ── updateSpacesDoc / writeSpaces CAS hardening ────────────────────────────────

const SPACES_PULL = defaultSpaceLayout.spacesPull("u1")

function makeSpacesClient(opts: {
  pull?: () => Promise<{ data: unknown; hash: string } | null>
  push?: () => Promise<{ hash: string; timestamp: number }>
  peek?: () => Promise<{ data: unknown; hash: string } | null>
}): { client: unknown; pullSpy: ReturnType<typeof vi.fn>; pushSpy: ReturnType<typeof vi.fn>; peekSpy: ReturnType<typeof vi.fn> } {
  const pullSpy = vi.fn(opts.pull ?? (async () => ({
    data: { v: 1, spaces: [], caps: {}, pubAccess: {} }, hash: "H_good",
  })))
  const pushSpy = vi.fn(opts.push ?? (async () => ({ hash: "H_new", timestamp: 1 })))
  const peekSpy = vi.fn(opts.peek ?? (async () => null))
  return {
    client: { pull: pullSpy, push: pushSpy, peekCache: peekSpy },
    pullSpy, pushSpy, peekSpy,
  }
}

function makeSpacesSession(): Session {
  return { userId: "u1", layout: defaultSpaceLayout } as Session
}

describe("updateSpacesDoc / writeSpaces — CAS hardening (regression + convergence)", () => {
  it("S1: regression — never calls pull() with staleWhileRevalidate (write paths must be network-first)", async () => {
    vi.useFakeTimers()
    const { client, pullSpy } = makeSpacesClient({})
    const p = writeSpaces(client as never, makeSpacesSession(), [{ id: "sp1", name: "W", members: 1 }])
    await vi.runAllTimersAsync()
    await p
    // pull must NOT be called with { staleWhileRevalidate: true } — that's the bug we fixed
    for (const args of pullSpy.mock.calls) {
      expect(args[1]).not.toEqual(expect.objectContaining({ staleWhileRevalidate: true }))
    }
  })

  it("S2: converges after a 409 — retry does a fresh pull and succeeds", async () => {
    vi.useFakeTimers()
    let attempt = 0
    const { client, pullSpy, pushSpy } = makeSpacesClient({
      pull: async () => {
        // First pull returns stale H0; second pull (on retry) returns advanced H1
        return attempt === 0
          ? { data: { v: 1, spaces: [], caps: {}, pubAccess: {} }, hash: "H0" }
          : { data: { v: 1, spaces: [], caps: {}, pubAccess: {} }, hash: "H1" }
      },
      push: async () => {
        if (++attempt === 1) throw new ConflictError("", 409)  // no currentHash (TS server)
        return { hash: "H_new", timestamp: 1 }
      },
    })
    const p = writeSpaces(client as never, makeSpacesSession(), [{ id: "sp1", name: "W", members: 1 }])
    await vi.runAllTimersAsync()
    await expect(p).resolves.toBeUndefined()
    expect(pushSpy).toHaveBeenCalledTimes(2)
    // Second push must use H1 (the fresh pull hash), not H0 (the stale one)
    const secondBaseHash = pushSpy.mock.calls[1][2]
    expect(secondBaseHash).toBe("H1")
    // Fresh pull was triggered on retry (second pull call without staleWhileRevalidate)
    expect(pullSpy).toHaveBeenCalledTimes(2)
  })

  it("S3: degraded pull (hash:'') + peekCache hit → push uses the good cached hash", async () => {
    vi.useFakeTimers()
    const { client, pushSpy, peekSpy } = makeSpacesClient({
      pull: async () => ({ data: {}, hash: "" }),  // degraded server read
      peek: async () => ({ data: { v: 1, spaces: [], caps: {}, pubAccess: {} }, hash: "H_cached" }),
    })
    const p = writeSpaces(client as never, makeSpacesSession(), [{ id: "sp1", name: "W", members: 1 }])
    await vi.runAllTimersAsync()
    await p
    expect(peekSpy).toHaveBeenCalledWith(SPACES_PULL)
    expect(pushSpy).toHaveBeenCalledTimes(1)
    const baseHash = pushSpy.mock.calls[0][2]
    expect(baseHash).toBe("H_cached")  // good cached hash, not ""
  })

  it("S4: warm in-memory cache is used on first attempt (no pull call)", async () => {
    vi.useFakeTimers()
    const { client, pullSpy, pushSpy } = makeSpacesClient({})
    // Pre-populate the doc-cache by running one successful write first
    const p1 = writeSpaces(client as never, makeSpacesSession(), [])
    await vi.runAllTimersAsync()
    await p1
    pullSpy.mockClear()  // reset call count
    // Second write should use the warm cache — no pull needed
    const p2 = writeSpaces(client as never, makeSpacesSession(), [{ id: "sp2", name: "W2", members: 1 }])
    await vi.runAllTimersAsync()
    await p2
    expect(pullSpy).not.toHaveBeenCalled()
    expect(pushSpy).toHaveBeenCalledTimes(2)
  })

  it("S5: mutator returning cur (no change) skips push", async () => {
    vi.useFakeTimers()
    const { client, pushSpy } = makeSpacesClient({})
    const p = updateSpacesDoc(client as never, makeSpacesSession(), (cur) => cur)
    await vi.runAllTimersAsync()
    await p
    expect(pushSpy).not.toHaveBeenCalled()
  })
})

describe("readSpaces — network-first (no staleWhileRevalidate)", () => {
  it("regression: ignores a pre-populated cache entry and always hits the network", async () => {
    // This is the actual race: StarfishClient.push() write-through to the pull
    // cache is fire-and-forget (unawaited `void this.cache.set(...)`), so an
    // SWR-enabled read could serve a cache entry written by a push that raced
    // ahead of (or lagged behind) the real server state. Proving readSpaces()
    // never consults the cache — regardless of what's in it — closes that race
    // categorically rather than depending on timing.
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

    const fetchMock = vi.fn().mockResolvedValueOnce(
      jsonResponse({ data: freshPayload, hash: "hfresh", timestamp: 10 }),
    )
    const client = new StarfishClient({
      baseUrl: "https://h",
      fetch: fetchMock as unknown as typeof fetch,
      cache,
    })

    const doc = await readSpaces(client, makeSession() as Session)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(doc.spaces).toEqual([{ id: "s1" }, { id: "s2" }])
    expect(doc.hash).toBe("hfresh")
  })

  it("regression: never calls pull() with { staleWhileRevalidate: true }", async () => {
    const pullSpy = vi.fn(async () => ({ data: { spaces: [], caps: {}, pubAccess: {} }, hash: "h1" }))
    const client = { pull: pullSpy }
    await readSpaces(client as never, makeSession() as Session)
    expect(pullSpy).toHaveBeenCalledTimes(1)
    const args = pullSpy.mock.calls[0]
    expect(args[1]).not.toEqual(expect.objectContaining({ staleWhileRevalidate: true }))
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
