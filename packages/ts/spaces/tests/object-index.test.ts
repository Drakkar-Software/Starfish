/**
 * Tests for updateObjectIndex — baseHash contract.
 *
 * The server CAS contract (push.py:106-112):
 *
 *   if base_hash is None:
 *     if raw: 409  ← None + existing doc = deadlock
 *   else:
 *     if base_hash != current_hash: 409
 *
 * Consequences:
 *   - missing doc     : pull hash=""  → send "" → else: ""!="" → FALSE → accept (create) ✓
 *   - hash-less doc   : pull hash=""  → send "" → else: ""==""  → FALSE → accept (heal) ✓
 *   - healthy doc     : pull hash="H" → send "H" → else: "H"!="H" → FALSE → accept ✓
 *   - null baseHash   : pull hash=""  → send null → None + raw → 409 forever ✗ (alpha.47 bug)
 *
 * U1: empty pull hash → baseHash="" sent (NOT null) — core regression guard
 * U2: non-empty pull hash → baseHash=real hash sent
 * U3: mutator returning null → no push (idempotency guard)
 * U4: mutator receives existing nodes from pull data
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ConflictError } from "@drakkar.software/starfish-client"
import type { Session } from "../src/session.js"
import { updateObjectIndex } from "../src/object-index.js"
import { clearDocCache } from "../src/doc-cache.js"

// Use a unique spaceId per test so the space-access-store cache
// never returns a stale entry (keyed by spaceId).
let _counter = 0
function nextSpaceId() { return `sp-objindex-test-${++_counter}` }

function makeTestSession(pullResult: { data: Record<string, unknown>; hash: string }) {
  const pushSpy = vi.fn(async () => ({ hash: "H_new", timestamp: 1 }))
  const pullSpy = vi.fn(async () => pullResult)
  const client = {
    pull: pullSpy,
    push: pushSpy,
  } as unknown as StarfishClient

  // session.contentClient is used by getSpaceClient when no access entry is cached.
  const session = {
    contentClient: client,
    layout: {
      objIndexPull: (id: string) => `/pull/spaces/${id}/objects/_index`,
      objIndexPush: (id: string) => `/push/spaces/${id}/objects/_index`,
    },
    baseUrl: "http://test",
    namespace: "test",
    userId: "u1",
    keys: { edPriv: "deadbeef" },
  } as unknown as Session

  return { session, pushSpy, pullSpy }
}

beforeEach(() => clearDocCache())

describe("updateObjectIndex — baseHash contract", () => {
  it("U1: sends baseHash='' (not null) when pull returns hash:'' — enables server heal path", async () => {
    const spaceId = nextSpaceId()
    const { session, pushSpy } = makeTestSession({ data: {}, hash: "" })

    await updateObjectIndex(session, spaceId, (_nodes) => [])

    const [, , baseHash] = pushSpy.mock.calls[0]
    // Must be "" not null. null hits: base_hash is None + raw → 409 forever.
    // "" hits:  else: "" != current_hash → if current_hash=="" (hash-less doc): no conflict → heal.
    expect(baseHash).toBe("")
    expect(baseHash).not.toBeNull()
  })

  it("U2: sends baseHash=stored hash when pull returns a non-empty hash", async () => {
    const spaceId = nextSpaceId()
    const storedHash = "sha256:deadbeef"
    const { session, pushSpy } = makeTestSession({
      data: { v: 2, objects: [], updatedAt: 0 },
      hash: storedHash,
    })

    await updateObjectIndex(session, spaceId, (nodes) => nodes)

    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe(storedHash)
  })

  it("U3: mutator returning null skips push entirely (idempotent on already-present node)", async () => {
    const spaceId = nextSpaceId()
    const { session, pushSpy } = makeTestSession({
      data: { v: 2, objects: [{ id: "n1", type: "wedding" }], updatedAt: 0 },
      hash: "H1",
    })

    await updateObjectIndex(session, spaceId, (nodes) => {
      if (nodes.some((n) => (n as { id: string }).id === "n1")) return null
      return nodes
    })

    expect(pushSpy).not.toHaveBeenCalled()
  })

  it("U4: mutator receives the existing nodes parsed from pull data", async () => {
    const spaceId = nextSpaceId()
    const existingNodes = [
      { id: "n1", type: "wedding", access: "space", enc: true },
      { id: "n2", type: "guest", access: "space", enc: true },
    ]
    const { session, pushSpy } = makeTestSession({
      data: { v: 2, objects: existingNodes, updatedAt: 0 },
      hash: "H2",
    })

    const receivedNodes: unknown[] = []
    await updateObjectIndex(session, spaceId, (nodes) => {
      receivedNodes.push(...nodes)
      return nodes
    })

    expect(receivedNodes).toHaveLength(2)
    expect((receivedNodes[0] as { id: string }).id).toBe("n1")
    expect((receivedNodes[1] as { id: string }).id).toBe("n2")
    // Push should have been called with the real hash from pull
    const [, , baseHash] = pushSpy.mock.calls[0]
    expect(baseHash).toBe("H2")
  })
})

describe("updateObjectIndex — warm-cache (octochat-style hash persistence)", () => {
  it("W1: second call reuses cached hash — no second pull", async () => {
    const spaceId = nextSpaceId()
    const { session, pushSpy, pullSpy } = makeTestSession({
      data: { v: 2, objects: [], updatedAt: 0 },
      hash: "H_initial",
    })
    // pushSpy returns H_new on first call, H_newer on second
    pushSpy
      .mockResolvedValueOnce({ hash: "H_new", timestamp: 1 })
      .mockResolvedValueOnce({ hash: "H_newer", timestamp: 2 })

    await updateObjectIndex(session, spaceId, (nodes) => nodes)  // cold → pulls, caches H_new
    await updateObjectIndex(session, spaceId, (nodes) => nodes)  // warm → no pull, uses H_new

    expect(pullSpy).toHaveBeenCalledTimes(1)   // only the first call pulled
    expect(pushSpy).toHaveBeenCalledTimes(2)
    const [, , baseHash1] = pushSpy.mock.calls[0]
    const [, , baseHash2] = pushSpy.mock.calls[1]
    expect(baseHash1).toBe("H_initial")        // first push used the pulled hash
    expect(baseHash2).toBe("H_new")            // second push used the cached hash from first push
  })

  it("W2: stale-cache 409 → re-pull with authoritative hash → retry succeeds", async () => {
    const spaceId = nextSpaceId()
    // First call: cold cache → pull → push → warm cache
    const { session, pushSpy, pullSpy } = makeTestSession({
      data: { v: 2, objects: [], updatedAt: 0 },
      hash: "H_initial",
    })
    pushSpy.mockResolvedValueOnce({ hash: "H_cached", timestamp: 1 })
    await updateObjectIndex(session, spaceId, (nodes) => nodes)
    // Cache is now warm: { hash: "H_cached" }

    // Second call: another device wrote → server now has H_fresh.
    // Push throws ConflictError (409) with currentHash="H_fresh" on first try,
    // then succeeds on retry (after re-pull).
    pullSpy.mockResolvedValue({ data: { v: 2, objects: [], updatedAt: 0 }, hash: "H_fresh" })
    pushSpy
      .mockRejectedValueOnce(new ConflictError("H_fresh"))
      .mockResolvedValueOnce({ hash: "H_after_retry", timestamp: 3 })

    await updateObjectIndex(session, spaceId, (nodes) => nodes)

    // The 409 must have triggered a re-pull (second pull call)
    expect(pullSpy).toHaveBeenCalledTimes(2)
    // Retry push carries the authoritative hash from the conflict / re-pull
    const calls = pushSpy.mock.calls
    expect(calls).toHaveLength(3)
    const retryBaseHash = calls[2][2]
    expect(retryBaseHash).toBe("H_fresh")
  })
})
