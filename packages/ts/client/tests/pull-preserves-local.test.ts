import { describe, it, expect, vi } from "vitest"
import type { Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishStore } from "../src/bindings/zustand.js"
import { createUnionMerge } from "../src/resolvers.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

// Regression coverage for the "lost message" bug: a plain pull() must NOT clobber
// un-pushed optimistic writes. A `set()` only mutates store.data (and marks dirty);
// the write reaches `SyncManager.localData` only on push-success. So when a pull
// runs while the store is dirty — fired by another client's write arriving over
// SSE, a poll, or a focus re-pull — the binding must MERGE the pulled snapshot with
// the current store data via the configured resolver, not overwrite it. The merge
// must happen at the STORE level: a SyncManager-only test never exercises the
// store.data-vs-getData() overwrite that actually drops the write.

// Reversible stub Encryptor (mirrors sync-encryptor.test.ts): wraps the JSON
// payload under `_encrypted`. Exercises the real E2EE pull path (encrypted rooms
// always decrypt a full snapshot, which is exactly where the overwrite bit users).
function stubEncryptor(): Encryptor {
  return {
    async encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>> {
      return { _encrypted: JSON.stringify(data) }
    },
    async decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>> {
      const blob = wrapper._encrypted
      if (typeof blob !== "string") {
        throw new Error("Expected encrypted data but received unencrypted document")
      }
      return JSON.parse(blob)
    },
  }
}

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
} = {}) {
  return {
    pull: overrides.pull ?? vi.fn(async () => ({ data: {}, hash: "h0", timestamp: 0 })),
    push: overrides.push ?? vi.fn(async () => ({ hash: "h1", timestamp: 1 })),
  } as unknown as StarfishClient
}

const ids = (msgs: unknown[]) => (msgs as Array<{ id: string }>).map((m) => m.id).sort()

describe("createStarfishStore.pull preserves un-pushed local writes", () => {
  it("merges a dirty local write into the pulled snapshot (E2EE room)", async () => {
    const enc = stubEncryptor()
    const m1 = { id: "m1", authorId: "me", ts: 100, text: "mine" }
    const m2 = { id: "m2", authorId: "other", ts: 110, text: "theirs" }

    // Server has only the OTHER user's message — our m1 was never pushed.
    const client = mockClient({
      pull: vi.fn(async () => ({ data: await enc.encrypt({ messages: [m2] }), hash: "h1", timestamp: 110 })),
    })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/r",
      pushPath: "/push/r",
      encryptor: enc,
      onConflict: createUnionMerge(),
    })
    const store = createStarfishStore({ name: "r", syncManager, storage: false })

    // Offline so set() does not auto-flush: m1 stays an un-pushed dirty write,
    // exactly the state a pull races against.
    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, messages: [...((d.messages as unknown[]) ?? []), m1] }))
    expect(store.getState().dirty).toBe(true)

    await store.getState().pull()

    // Both survive — m1 is NOT clobbered by the server snapshot.
    expect(ids((store.getState().data.messages as unknown[]) ?? [])).toEqual(["m1", "m2"])
  })

  it("replaces with the remote snapshot when the store is clean (steady state)", async () => {
    const enc = stubEncryptor()
    const m2 = { id: "m2", authorId: "other", ts: 110 }
    const client = mockClient({
      pull: vi.fn(async () => ({ data: await enc.encrypt({ messages: [m2] }), hash: "h1", timestamp: 110 })),
    })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/r",
      pushPath: "/push/r",
      encryptor: enc,
      onConflict: createUnionMerge(),
    })
    const store = createStarfishStore({ name: "r", syncManager, storage: false })

    // Not dirty → pull takes the server snapshot verbatim (no spurious resolve).
    await store.getState().pull()
    expect(store.getState().data).toEqual({ messages: [m2] })
  })

  it("re-flushes the preserved write so it reaches the server (online + dirty)", async () => {
    const enc = stubEncryptor()
    const m1 = { id: "m1", authorId: "me", ts: 100 }
    const m2 = { id: "m2", authorId: "other", ts: 110 }

    // First push fails (transient) so m1 stays dirty/unpushed even while online;
    // subsequent pushes succeed. The pull's flush-kick must send m1.
    let pushCount = 0
    const pushFn = vi.fn(async () => {
      pushCount++
      if (pushCount === 1) throw new Error("transient network error")
      return { hash: "h2", timestamp: 120 }
    })
    const client = mockClient({
      pull: vi.fn(async () => ({ data: await enc.encrypt({ messages: [m2] }), hash: "h1", timestamp: 110 })),
      push: pushFn as never,
    })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/r",
      pushPath: "/push/r",
      encryptor: enc,
      onConflict: createUnionMerge(),
      maxRetries: 0,
    })
    const store = createStarfishStore({ name: "r", syncManager, storage: false })

    // Online: set() auto-flushes, but that first push fails → still dirty.
    store.getState().set((d) => ({ ...d, messages: [m1] }))
    await vi.waitFor(() => expect(pushCount).toBe(1))
    expect(store.getState().dirty).toBe(true)

    await store.getState().pull()

    // The pull-triggered flush pushes the merged (m1 + m2) doc and clears dirty.
    await vi.waitFor(() => {
      expect(pushCount).toBe(2)
      expect(store.getState().dirty).toBe(false)
    })
    const pushed = await enc.decrypt(pushFn.mock.calls[1][1] as Record<string, unknown>)
    expect(ids((pushed.messages as unknown[]) ?? [])).toEqual(["m1", "m2"])
  })

  it("preserves a dirty local write for plaintext (public) rooms too", async () => {
    const m1 = { id: "m1", authorId: "me", ts: 100 }
    const m2 = { id: "m2", authorId: "other", ts: 110 }
    // No encryptor → public/plaintext room. Same store-level merge must apply.
    const client = mockClient({
      pull: vi.fn(async () => ({ data: { messages: [m2] }, hash: "h1", timestamp: 110 })),
    })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/p",
      pushPath: "/push/p",
      onConflict: createUnionMerge(),
    })
    const store = createStarfishStore({ name: "p", syncManager, storage: false })

    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, messages: [...((d.messages as unknown[]) ?? []), m1] }))
    await store.getState().pull()

    expect(ids((store.getState().data.messages as unknown[]) ?? [])).toEqual(["m1", "m2"])
  })
})
