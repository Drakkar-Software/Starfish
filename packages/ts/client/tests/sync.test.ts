import { describe, it, expect, vi } from "vitest"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { deepMerge } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createUnionMerge } from "../src/resolvers.js"
import { ConflictError } from "../src/types.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

// Reversible stub Encryptor: wraps the JSON payload under `_encrypted`.
function stubEncryptor(): Encryptor {
  return {
    async encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>> {
      return { _encrypted: JSON.stringify(data) }
    },
    async decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>> {
      const blob = wrapper._encrypted
      if (typeof blob !== "string") throw new Error("not encrypted")
      return JSON.parse(blob)
    },
  }
}

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
  peekCache?: (path: string) => Promise<PullResponse | null>
} = {}) {
  const client = {
    pull: overrides.pull ?? vi.fn(async () => ({
      data: { key: "value" },
      hash: "abc123",
      timestamp: 1000,
    })),
    push: overrides.push ?? vi.fn(async () => ({
      hash: "def456",
      timestamp: 2000,
    })),
    // seedFromCache() calls peekCache; default to null (no cache hit) so
    // existing tests that never call seedFromCache() are unaffected.
    peekCache: overrides.peekCache ?? vi.fn(async () => null),
  } as unknown as StarfishClient

  return client
}

describe("SyncManager", () => {
  it("pull stores data, hash, and checkpoint", async () => {
    const client = mockClient()
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.pull()
    expect(result.data).toEqual({ key: "value" })
    expect(sync.getData()).toEqual({ key: "value" })
    expect(sync.getHash()).toBe("abc123")
    expect(sync.getCheckpoint()).toBe(1000)
  })

  it("push sends data and updates state", async () => {
    const pushFn = vi.fn(async () => ({ hash: "new-hash", timestamp: 3000 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.push({ newKey: "newValue" })
    expect(result.hash).toBe("new-hash")
    expect(result.timestamp).toBe(3000)
    expect(sync.getHash()).toBe("new-hash")
    // No signer configured → author proof is undefined (4th arg).
    expect(pushFn).toHaveBeenCalledWith(
      "/push/test",
      { newKey: "newValue" },
      null,
      undefined,
    )
  })

  it("incremental pull merges into local data", async () => {
    let callCount = 0
    const client = mockClient({
      pull: async () => {
        callCount++
        if (callCount === 1) {
          return { data: { a: 1, b: 2 }, hash: "h1", timestamp: 100 }
        }
        return { data: { b: 3 }, hash: "h2", timestamp: 200 }
      },
    })

    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    await sync.pull() // full pull
    expect(sync.getData()).toEqual({ a: 1, b: 2 })

    await sync.pull() // incremental — should merge
    expect(sync.getData()).toEqual({ a: 1, b: 3 })
  })

  it("incremental pull replaces an array wholesale and preserves local-only keys", async () => {
    // deepMerge is not element-wise: a remote array replaces the local one (not
    // concatenated), while a local-only key survives. Pins the merge contract
    // through the client's incremental path. Mirrors test_sync.py.
    let callCount = 0
    const client = mockClient({
      pull: async () => {
        callCount++
        if (callCount === 1) return { data: { items: [1, 2, 3], k: "v" }, hash: "h1", timestamp: 100 }
        return { data: { items: [9] }, hash: "h2", timestamp: 200 }
      },
    })
    const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })

    await sync.pull()
    expect(sync.getData()).toEqual({ items: [1, 2, 3], k: "v" })
    await sync.pull() // incremental merge
    expect(sync.getData()).toEqual({ items: [9], k: "v" })
  })

  it("update does pull-modify-push", async () => {
    const pushFn = vi.fn(async () => ({ hash: "updated", timestamp: 500 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const result = await sync.update((data) => ({
      ...data,
      extra: "field",
    }))

    expect(result.hash).toBe("updated")
    expect(pushFn).toHaveBeenCalled()
  })

  it("push retries on conflict, merges via onConflict, and succeeds", async () => {
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new ConflictError()
      return { hash: "merged-hash", timestamp: 3000 }
    })
    let pullCount = 0
    const pullFn = vi.fn(async () => {
      pullCount++
      if (pullCount === 1) return { data: { a: 1 }, hash: "h1", timestamp: 100 }
      // Re-pull during conflict resolution
      return { data: { a: 1, remote: true }, hash: "h2", timestamp: 200 }
    })
    const onConflict = vi.fn((local: Record<string, unknown>, remote: Record<string, unknown>) => ({
      ...remote,
      ...local,
    }))

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict,
    })

    await sync.pull()
    const result = await sync.push({ a: 1, local: true })

    expect(result.hash).toBe("merged-hash")
    expect(onConflict).toHaveBeenCalledWith(
      { a: 1, local: true },
      { a: 1, remote: true },
    )
    expect(pushFn).toHaveBeenCalledTimes(2)
    expect(sync.getHash()).toBe("merged-hash")
  })

  it("propagates an error thrown by a custom conflict resolver (not swallowed)", async () => {
    // A resolver that rejects the merge (e.g. a validation failure) must surface
    // its error to the caller rather than be silently swallowed. Mirrors test_sync.py.
    const pushFn = vi.fn(async () => { throw new ConflictError() })
    const pullFn = vi.fn(async () => ({ data: { a: 1 }, hash: "h1", timestamp: 100 }))
    const onConflict = vi.fn(() => { throw new Error("merge rejected by validator") })
    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict,
    })

    await sync.pull()
    await expect(sync.push({ a: 2 })).rejects.toThrow("merge rejected by validator")
    expect(onConflict).toHaveBeenCalled()
  })

  it("push throws ConflictError after exhausting maxRetries", async () => {
    const pushFn = vi.fn(async () => { throw new ConflictError() })
    const pullFn = vi.fn(async () => ({
      data: { remote: true },
      hash: "h-remote",
      timestamp: 100,
    }))

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      maxRetries: 1,
    })

    await sync.pull()
    await expect(sync.push({ local: true })).rejects.toThrow("hash_mismatch")
    // 1 initial + 1 retry = 2 attempts
    expect(pushFn).toHaveBeenCalledTimes(2)
  })

  // A faithful stateful "server": a push succeeds only when its baseHash equals
  // the server's current hash (push.ts: `baseHash !== currentHash` → 409
  // ConflictError); the loser conflict-retries (pull → default deepMerge → retry).
  function statefulClient(initialHash: string, initialData: Record<string, unknown>) {
    const state = { hash: initialHash, data: initialData }
    const push = vi.fn(async (_p: string, data: Record<string, unknown>, baseHash: string | null) => {
      if (baseHash !== state.hash) throw new ConflictError()
      state.data = data
      state.hash = "h-" + JSON.stringify(data)
      return { hash: state.hash, timestamp: 1 }
    })
    const pull = vi.fn(async () => ({ data: state.data, hash: state.hash, timestamp: 1 }))
    return { client: mockClient({ pull: pull as any, push: push as any }), state, push, pull }
  }

  it("two concurrent push() calls on the same manager both land (no lost write)", async () => {
    const { client, state, push } = statefulClient("h0", {})
    const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
    sync.setHash("h0") // both pushes start from the same baseHash
    await Promise.all([sync.push({ x: 1 }), sync.push({ y: 2 })])
    // Observable invariant: the loser conflict-retries and the default deepMerge
    // unions both writes — neither is lost. (One push lands directly, the other
    // takes a second attempt.)
    expect(state.data).toEqual({ x: 1, y: 2 })
    expect(push.mock.calls.length).toBeGreaterThanOrEqual(3) // 1 winner + (1 conflict + 1 retry)
  })

  it("a stale/corrupt persisted hash self-heals through the conflict-retry loop", async () => {
    // Rehydrating a truncated/garbage hash from storage makes the first push 409
    // (it can't match the real current hash); the retry loop pulls, merges, and
    // re-pushes against the real hash. The server treats *any* non-matching
    // baseHash as a conflict (not a 400), so recovery is automatic.
    const { client, state, push } = statefulClient("real-hash", { a: 1 })
    const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
    sync.setHash("truncated-garbage")
    const result = await sync.push({ b: 2 })
    expect(push).toHaveBeenCalledTimes(2) // 1 conflict + 1 successful retry
    expect(state.data).toEqual({ a: 1, b: 2 })
    expect(result.hash).toBe(state.hash)
  })

  it("push logs conflict resolution failure when re-pull fails", async () => {
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new ConflictError()
      return { hash: "h", timestamp: 1 }
    })
    const pullFn = vi.fn(async () => {
      if (pullFn.mock.calls.length > 1) throw new Error("network down")
      return { data: {}, hash: "h1", timestamp: 100 }
    })
    const pushError = vi.fn()

    const client = mockClient({ pull: pullFn as any, push: pushFn as any })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      logger: {
        pullStart: () => {},
        pullSuccess: () => {},
        pullError: () => {},
        pushStart: () => {},
        pushSuccess: () => {},
        pushError,
        conflict: () => {},
      },
    })

    await sync.pull()
    await expect(sync.push({ x: 1 })).rejects.toThrow("network down")
    expect(pushError).toHaveBeenCalledWith(
      expect.any(String),
      expect.stringContaining("Conflict resolution failed"),
    )
  })

})

// ── pull/ingest honor onConflict ──────────────────────────────────────────────
//
// Regression: the incremental-pull and ingest paths previously hardcoded
// deepMerge, so a store configured with createUnionMerge still lost array items
// whenever a pull/revalidation returned a shorter array.  Both paths now route
// through this.onConflict when a checkpoint is established.  onConflict defaults
// to deepMerge, so stores without a custom resolver behave identically.

describe("SyncManager pull/ingest honor onConflict", () => {
  it("non-breaking: default (deepMerge) still replaces an array wholesale on pull", async () => {
    // Asserts the existing contract is preserved when no custom resolver is set.
    let n = 0
    const client = mockClient({
      pull: async () => {
        n++
        if (n === 1) return { data: { items: [1, 2, 3], k: "v" }, hash: "h1", timestamp: 100 }
        return { data: { items: [9] }, hash: "h2", timestamp: 200 }
      },
    })
    const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
    await sync.pull()
    await sync.pull()
    expect(sync.getData()).toEqual({ items: [9], k: "v" })
  })

  it("plaintext pull with createUnionMerge preserves items missing from a shorter snapshot", async () => {
    // The iOS regression: a cache-fallback or concurrent-write snapshot carries
    // only the category nodes — room nodes must NOT be dropped.
    let n = 0
    const client = mockClient({
      pull: async () => {
        n++
        if (n === 1) return { data: { objects: [{ id: "cat-1" }, { id: "r1" }, { id: "r2" }] }, hash: "h1", timestamp: 100 }
        return { data: { objects: [{ id: "cat-1" }] }, hash: "h2", timestamp: 200 }
      },
    })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })
    await sync.pull()
    await sync.pull()
    const ids = (sync.getData().objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["cat-1", "r1", "r2"])
  })

  it("E2EE pull with createUnionMerge preserves items from a shorter decrypted snapshot", async () => {
    const enc = stubEncryptor()
    let n = 0
    const client = mockClient({
      pull: async () => {
        n++
        const payload =
          n === 1
            ? { objects: [{ id: "cat-1" }, { id: "r1" }, { id: "r2" }] }
            : { objects: [{ id: "cat-1" }] }
        return { data: await enc.encrypt(payload), hash: `h${n}`, timestamp: n * 100 }
      },
    })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      encryptor: enc,
      onConflict: createUnionMerge(),
    })
    await sync.pull()
    await sync.pull()
    const ids = (sync.getData().objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["cat-1", "r1", "r2"])
  })

  it("ingest with createUnionMerge preserves items from a shorter revalidation snapshot", async () => {
    const client = mockClient({
      pull: async () => ({
        data: { objects: [{ id: "cat-1" }, { id: "r1" }, { id: "r2" }] },
        hash: "h1",
        timestamp: 100,
      }),
    })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })
    await sync.pull() // establishes checkpoint 100

    // Background revalidation returns a shorter snapshot.
    await sync.ingest({ data: { objects: [{ id: "cat-1" }] }, hash: "h2", timestamp: 200 })
    const ids = (sync.getData().objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["cat-1", "r1", "r2"])
  })

  it("ingest staleness guard still drops a result older than lastCheckpoint", async () => {
    const client = mockClient({
      pull: async () => ({ data: { objects: [{ id: "r1" }] }, hash: "h1", timestamp: 200 }),
    })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })
    await sync.pull() // lastCheckpoint = 200

    // Stale revalidation snapshot (timestamp 100 < 200) must be silently dropped.
    await sync.ingest({ data: { objects: [] }, hash: "h0", timestamp: 100 })
    const ids = (sync.getData().objects as Array<{ id: string }>).map((o) => o.id)
    expect(ids).toEqual(["r1"])
  })

  it("newer updatedAt in incoming wins (rename flows through on pull)", async () => {
    let n = 0
    const client = mockClient({
      pull: async () => {
        n++
        if (n === 1) return { data: { objects: [{ id: "r1", updatedAt: 1000, title: "Old" }] }, hash: "h1", timestamp: 100 }
        return { data: { objects: [{ id: "r1", updatedAt: 2000, title: "New" }] }, hash: "h2", timestamp: 200 }
      },
    })
    const sync = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge({ idKey: "id", timestampKey: "updatedAt" }),
    })
    await sync.pull()
    await sync.pull()
    const item = (sync.getData().objects as Array<{ id: string; title: string }>)[0]
    expect(item.title).toBe("New")
  })

  // ── bootstrap window (seed → first pull) ────────────────────────────────────
  //
  // Root of the OctoChat iOS bug: when the object-index store is evicted
  // (refCount→0 on home→room→back) and rebuilt, acquireSyncStore runs
  // seed().finally(pull()).  seedFromCache() sets localData but leaves
  // lastCheckpoint=0.  The first pull() gated on `lastCheckpoint > 0` then
  // takes the server snapshot wholesale — bypassing onConflict — so a shorter
  // first response (cache-fallback on 429/5xx, or a momentarily-short
  // concurrent snapshot) silently drops room nodes from the index.

  it("REPRO: seedFromCache + union pull — first pull must NOT drop seed items (RED on alpha.36)", async () => {
    // Seed: cache has both 'a' and 'b'.  First live pull returns only 'a'.
    // With createUnionMerge the seed is the baseline — 'b' must survive.
    const seedItems = [{ id: "a", updatedAt: 1 }, { id: "b", updatedAt: 1 }]
    const client = mockClient({
      peekCache: async () => ({ data: { items: seedItems }, hash: "h0", timestamp: 0 }),
      pull: async () => ({ data: { items: [{ id: "a", updatedAt: 2 }] }, hash: "h1", timestamp: 5 }),
    })
    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge({ idKey: "id", timestampKey: "updatedAt" }),
    })
    expect(await sm.seedFromCache()).toBe(true)
    await sm.pull()
    const ids = (sm.getData().items as Array<{ id: string }>).map((x) => x.id).sort()
    // GREEN after fix: both items survive.  RED on alpha.36: only ['a'].
    expect(ids).toEqual(["a", "b"])
  })

  it("seedFromCache + union ingest — revalidation snapshot must NOT drop seed items", async () => {
    const seedObjects = [{ id: "cat" }, { id: "r1" }, { id: "r2" }]
    const client = mockClient({
      peekCache: async () => ({ data: { objects: seedObjects }, hash: "h0", timestamp: 0 }),
    })
    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })
    expect(await sm.seedFromCache()).toBe(true)
    // Ingest a shorter revalidation snapshot — union must preserve r1 and r2.
    await sm.ingest({ data: { objects: [{ id: "cat" }] }, hash: "h1", timestamp: 5 })
    const ids = (sm.getData().objects as Array<{ id: string }>).map((x) => x.id).sort()
    expect(ids).toEqual(["cat", "r1", "r2"])
  })

  it("seedFromCache + default deepMerge — first pull still wholesale (non-breaking proof)", async () => {
    // With the DEFAULT resolver (deepMerge), a cache seed must NOT change the
    // wholesale-replace behavior of the first pull.  If hasMergeBaseline() is
    // correctly gated on onConflict !== deepMerge, this stays byte-identical to
    // alpha.36 (GREEN before AND after the fix).
    const client = mockClient({
      peekCache: async () => ({ data: { items: [{ id: "a" }, { id: "b" }], extra: 1 }, hash: "h0", timestamp: 0 }),
      pull: async () => ({ data: { items: [{ id: "a" }] }, hash: "h1", timestamp: 5 }),
    })
    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      // no onConflict → deepMerge default
    })
    expect(await sm.seedFromCache()).toBe(true)
    await sm.pull()
    // deepMerge branch: first pull takes incoming wholesale — 'b' and 'extra' gone.
    expect(sm.getData()).toEqual({ items: [{ id: "a" }] })
  })
})

// ── bootstrap-window advanced interaction chains ──────────────────────────────
//
// These test the end-to-end chains that are the *actual* OctoChat regression
// scenario: seed → pull → push-conflict-retry. The three repro tests shipped
// with alpha.38 prove the fix at the unit level (seed→pull, seed→ingest); these
// cover the full multi-step combinations that were never tested.

describe("SyncManager bootstrap-window — advanced interaction edges", () => {
  // A1 — seed → union pull → push 409 → retry: seeded items survive the whole chain.
  // This is the literal regression scenario: the store is evicted (home→room→back),
  // rebuilt via seed+pull, then a push hits 409. The union merge in both the
  // pull and the retry must keep r1+r2 throughout.
  it("A1: seed → union pull → push 409 → retry — seeded rooms survive entire chain", async () => {
    const cat = { id: "cat" }
    const r1 = { id: "r1" }
    const r2 = { id: "r2" }

    let pushCount = 0
    const client = mockClient({
      peekCache: async () => ({ data: { objects: [cat, r1, r2] }, hash: "stale-h", timestamp: 0 }),
      pull: async () => ({ data: { objects: [cat] }, hash: "server-h0", timestamp: 10 }),
      push: vi.fn(async () => {
        pushCount++
        if (pushCount === 1) throw new ConflictError()
        return { hash: "server-h1", timestamp: 20 }
      }) as any,
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })

    await sm.seedFromCache()                          // localData = {objects:[cat,r1,r2]}
    await sm.pull()                                   // short first pull → union → still [cat,r1,r2]

    // Push a new edit; first attempt 409s; conflict re-pull returns short [cat] again;
    // union retry must keep r1+r2 AND the extra field.
    await sm.push({ objects: [cat, r1, r2], extra: "edit" })

    const data = sm.getData()
    const ids = (data.objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["cat", "r1", "r2"])
    expect(data.extra).toBe("edit")
  })

  // A2 — push directly after seed, NO pull (stale seed hash → 409 → union retry).
  // The seed's lastHash is the cached hash. A push with no intervening pull uses it
  // as baseHash, which may be stale → 409. The union merge in the retry must
  // preserve items from the seeded localData that the short re-pull snapshot omits.
  it("A2: push after seed with no pull — stale seed hash 409-retries and union preserves seed", async () => {
    const r1 = { id: "r1" }
    const r2 = { id: "r2" }
    const r3 = { id: "r3" }

    let pushCount = 0
    const client = mockClient({
      peekCache: async () => ({ data: { objects: [r1, r2] }, hash: "stale-seed-hash", timestamp: 0 }),
      pull: async () => ({ data: { objects: [r1] }, hash: "server-h", timestamp: 5 }),
      push: vi.fn(async () => {
        pushCount++
        if (pushCount === 1) throw new ConflictError()
        return { hash: "server-h2", timestamp: 10 }
      }) as any,
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })

    await sm.seedFromCache()  // lastHash = "stale-seed-hash"
    await sm.push({ objects: [r1, r2, r3] })  // no prior pull → baseHash = stale → 409

    const ids = (sm.getData().objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["r1", "r2", "r3"])
  })

  // A3 — seed → first pull THROWS (offline/429 with no fallback) → seeded baseline stays.
  // A throwing pull must not modify localData or lastFromCache.
  // "Rooms must stay visible when the first live pull fails."
  it("A3: seed → first pull throws (offline) — seeded data remains visible", async () => {
    const a = { id: "a" }
    const b = { id: "b" }

    const client = mockClient({
      peekCache: async () => ({ data: { items: [a, b] }, hash: "h0", timestamp: 0 }),
      pull: async () => { throw new Error("Network unreachable") },
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge(),
    })

    await sm.seedFromCache()
    expect(sm.getLastPullFromCache()).toBe(true)

    await expect(sm.pull()).rejects.toThrow("Network unreachable")

    // Seeded data must survive — pull threw before localData could be touched
    const ids = (sm.getData().items as Array<{ id: string }>).map((x) => x.id).sort()
    expect(ids).toEqual(["a", "b"])
    // lastFromCache was never cleared by the failing pull
    expect(sm.getLastPullFromCache()).toBe(true)
  })

  // A4 — seed holds a NEWER item than the first live pull (a locally-edited room).
  // The union merge's per-item updatedAt comparison must keep the seeded version.
  it("A4: seed-newer item beats stale server first-pull (per-item updatedAt wins)", async () => {
    const client = mockClient({
      peekCache: async () => ({
        data: { objects: [{ id: "r1", updatedAt: 5, title: "Local edit" }] },
        hash: "h0",
        timestamp: 0,
      }),
      pull: async () => ({
        data: { objects: [{ id: "r1", updatedAt: 2, title: "Stale server" }] },
        hash: "h1",
        timestamp: 10,
      }),
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: createUnionMerge({ idKey: "id", timestampKey: "updatedAt" }),
    })

    await sm.seedFromCache()
    await sm.pull()

    const r1 = (sm.getData().objects as Array<{ id: string; title: string }>).find(
      (o) => o.id === "r1",
    )
    expect(r1?.title).toBe("Local edit")  // seeded version was newer — must not be clobbered
  })

  // A5 — E2EE seed → union first pull: bootstrap must work through the encryptor.
  // peekCache returns an encrypted blob; seedFromCache decrypts it; the first
  // pull also returns encrypted; after decrypt + union all seeded items survive.
  // (Only the plaintext seed→union-pull path was covered by the alpha.38 repro.)
  it("A5: E2EE seed → union first pull — encrypted seed items survive bootstrap", async () => {
    const enc = stubEncryptor()
    const cat = { id: "cat" }
    const r1 = { id: "r1" }
    const r2 = { id: "r2" }

    const client = mockClient({
      peekCache: async () => ({
        data: await enc.encrypt({ objects: [cat, r1, r2] }),
        hash: "h0",
        timestamp: 0,
      }),
      pull: async () => ({
        data: await enc.encrypt({ objects: [cat] }),
        hash: "h1",
        timestamp: 5,
      }),
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      encryptor: enc,
      onConflict: createUnionMerge(),
    })

    expect(await sm.seedFromCache()).toBe(true)
    await sm.pull()

    const ids = (sm.getData().objects as Array<{ id: string }>).map((o) => o.id).sort()
    expect(ids).toEqual(["cat", "r1", "r2"])
  })

  // A6 — lastFromCache reset: seed sets it to true; a live (non-cache) pull must flip it false.
  // Tested starting from false everywhere today; the seed→live-pull TRANSITION is uncovered.
  it("A6: lastFromCache transitions from true (seed) to false (live pull)", async () => {
    const client = mockClient({
      peekCache: async () => ({ data: { x: 1 }, hash: "h0", timestamp: 0 }),
      pull: async () => ({ data: { x: 2 }, hash: "h1", timestamp: 5 }),
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    await sm.seedFromCache()
    expect(sm.getLastPullFromCache()).toBe(true)

    await sm.pull()
    // pullWasFromCache(result) is false for a plain mock response → lastFromCache cleared
    expect(sm.getLastPullFromCache()).toBe(false)
  })

  // A7 — explicit onConflict: deepMerge (the same reference as the default) → seed protection OFF.
  // hasMergeBaseline() gates on `this.onConflict !== deepMerge`. Passing the same symbol
  // explicitly keeps wholesale-replace on the first pull — byte-identical to alpha.36.
  it("A7: explicit onConflict: deepMerge (same ref) — seed protection OFF, first pull wholesale", async () => {
    const client = mockClient({
      peekCache: async () => ({
        data: { items: [{ id: "a" }, { id: "b" }] },
        hash: "h0",
        timestamp: 0,
      }),
      pull: async () => ({ data: { items: [{ id: "a" }] }, hash: "h1", timestamp: 5 }),
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: deepMerge,  // same ref as internal default → hasMergeBaseline() = false
    })

    await sm.seedFromCache()
    await sm.pull()

    // Protection OFF: first pull takes incoming wholesale — 'b' is dropped
    expect(sm.getData()).toEqual({ items: [{ id: "a" }] })
  })

  // A8 — wrapper around deepMerge (different reference) → seed protection ON.
  // vi.fn(deepMerge) delegates to deepMerge but is referentially !== deepMerge, so
  // hasMergeBaseline() returns true and the spy is called on the first post-seed pull.
  // A7 + A8 together pin the referential-identity contract of hasMergeBaseline().
  it("A8: onConflict wrapper around deepMerge (different ref) — protection ON, spy called on first pull", async () => {
    const seedItems = [{ id: "a" }, { id: "b" }]
    const spyResolver = vi.fn(deepMerge)  // wraps deepMerge; referentially !== deepMerge

    const client = mockClient({
      peekCache: async () => ({ data: { items: seedItems }, hash: "h0", timestamp: 0 }),
      pull: async () => ({ data: { items: [{ id: "a" }] }, hash: "h1", timestamp: 5 }),
    })

    const sm = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
      onConflict: spyResolver,
    })

    await sm.seedFromCache()
    await sm.pull()

    // hasMergeBaseline() returned true → onConflict was invoked with (seeded, incoming)
    expect(spyResolver).toHaveBeenCalledTimes(1)
    expect(spyResolver).toHaveBeenCalledWith(
      { items: seedItems },       // local = seeded snapshot
      { items: [{ id: "a" }] },  // remote = first live pull
    )
  })
})

// ── setHash ───────────────────────────────────────────────────────────────────

describe("SyncManager.setHash", () => {
  function makeSync() {
    const client = mockClient()
    return new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
  }

  it("sets the hash returned by getHash()", () => {
    const sync = makeSync()
    sync.setHash("h1")
    expect(sync.getHash()).toBe("h1")
  })

  it("accepts null to clear the hash", () => {
    const sync = makeSync()
    sync.setHash("h1")
    sync.setHash(null)
    expect(sync.getHash()).toBeNull()
  })

  it("next push sends the restored hash as baseHash", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h2", timestamp: 200 }))
    const client = mockClient({ push: pushFn as any })
    const sync = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })

    sync.setHash("restored-hash")
    await sync.push({ foo: "bar" })

    // Third positional arg to client.push is baseHash
    expect(pushFn.mock.calls[0][2]).toBe("restored-hash")
  })
})
