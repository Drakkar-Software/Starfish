import { describe, it, expect, vi } from "vitest"
// SyncManager.abort() must cancel an in-flight push or pull and leave
// lastHash / localData unchanged. Without abort(), clear() on a lazy wrapper
// can null the inner manager mid-push but the push completes later and writes
// stale state — or clearAllStarfishStores() wipes AsyncStorage and a late push
// re-persists the cleared data.
import { SyncManager } from "../src/sync.js"
import { AbortError } from "../src/sync.js"
import type { StarfishClient } from "../src/client.js"

function makeSlowPushClient(
  delay: number,
  result: { hash: string; timestamp: number } = { hash: "new-hash", timestamp: 200 },
) {
  let resolver!: (r: typeof result) => void
  const pending = new Promise<typeof result>((resolve) => { resolver = resolve })
  const client = {
    push: vi.fn(() => pending),
    pull: vi.fn(async () => ({ data: {}, hash: "initial-hash", timestamp: 100 })),
  } as unknown as StarfishClient
  return { client, resolvePush: () => resolver(result) }
}

// ─── abort during push ────────────────────────────────────────────────────────

describe("SyncManager.abort()", () => {
  it("rejects in-flight push with AbortError and leaves state unchanged", async () => {
    const { client, resolvePush } = makeSlowPushClient(50)
    const sync = new SyncManager({ client, pullPath: "/pull/x", pushPath: "/push/x" })
    sync.setHash("initial-hash")

    const pushPromise = sync.push({ x: 1 })

    // Abort before the push response is processed
    sync.abort()
    resolvePush()  // network call resolves — but abort should fire first

    await expect(pushPromise).rejects.toThrow(AbortError)
  })

  it("does not update lastHash or localData when aborted mid-push", async () => {
    const { client, resolvePush } = makeSlowPushClient(50)
    const sync = new SyncManager({ client, pullPath: "/pull/x", pushPath: "/push/x" })
    sync.setHash("initial-hash")

    const pushPromise = sync.push({ x: 1 })
    sync.abort()
    resolvePush()
    await pushPromise.catch(() => {})

    // State must be as it was before the push started
    expect(sync.getHash()).toBe("initial-hash")
    expect(sync.getData()).toEqual({})
  })

  it("exposes isAborted getter that reflects abort state", () => {
    const { client } = makeSlowPushClient(50)
    const sync = new SyncManager({ client, pullPath: "/pull/x", pushPath: "/push/x" })

    expect(sync.isAborted).toBe(false)
    sync.abort()
    expect(sync.isAborted).toBe(true)
  })

  it("push on an already-aborted manager rejects immediately", async () => {
    const { client } = makeSlowPushClient(50)
    const sync = new SyncManager({ client, pullPath: "/pull/x", pushPath: "/push/x" })

    sync.abort()
    await expect(sync.push({ x: 1 })).rejects.toThrow(AbortError)
    // client.push should not be called for a pre-aborted manager
    expect(client.push).not.toHaveBeenCalled()
  })

  // ─── abort during pull ────────────────────────────────────────────────────

  it("rejects in-flight pull with AbortError and leaves state unchanged", async () => {
    let resolvePull!: () => void
    const pullPending = new Promise<{ data: Record<string, unknown>; hash: string; timestamp: number }>(
      (resolve) => { resolvePull = () => resolve({ data: { k: 1 }, hash: "pulled-hash", timestamp: 500 }) }
    )
    const client = { pull: vi.fn(() => pullPending), push: vi.fn() } as unknown as StarfishClient
    const sync = new SyncManager({ client, pullPath: "/pull/x", pushPath: "/push/x" })

    const pullPromise = sync.pull()
    sync.abort()
    resolvePull()

    await expect(pullPromise).rejects.toThrow(AbortError)
    // Hash must not have been updated
    expect(sync.getHash()).toBeNull()
  })
})
