import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { ConflictError } from "../src/types.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
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
    expect(pushFn).toHaveBeenCalledWith(
      "/push/test",
      { newKey: "newValue" },
      null,
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
