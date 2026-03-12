import { describe, it, expect, vi } from "vitest"
import { produce } from "immer"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishObservable } from "../src/bindings/legend.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

function mockClient(overrides: {
  pull?: (path: string, checkpoint?: number) => Promise<PullResponse>
  push?: (path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>
} = {}) {
  return {
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
}

function createTestStore(clientOverrides?: Parameters<typeof mockClient>[0]) {
  const client = mockClient(clientOverrides)
  const syncManager = new SyncManager({
    client,
    pullPath: "/pull/test",
    pushPath: "/push/test",
  })
  const store = createStarfishObservable({ name: "test", syncManager })
  return { store, client, syncManager }
}

describe("createStarfishObservable", () => {
  it("has correct initial state", () => {
    const { store } = createTestStore()
    const { state } = store

    expect(state.data.get()).toEqual({})
    expect(state.syncing.get()).toBe(false)
    expect(state.online.get()).toBe(true)
    expect(state.dirty.get()).toBe(false)
    expect(state.error.get()).toBeNull()
  })

  it("pull fetches remote data into observable", async () => {
    const { store } = createTestStore()
    await store.pull()

    expect(store.state.data.get()).toEqual({ key: "value" })
    expect(store.state.syncing.get()).toBe(false)
    expect(store.state.error.get()).toBeNull()
  })

  it("pull sets error on failure", async () => {
    const { store } = createTestStore({
      pull: async () => { throw new Error("network down") },
    })

    await store.pull()

    expect(store.state.error.get()).toBe("network down")
    expect(store.state.syncing.get()).toBe(false)
    expect(store.state.data.get()).toEqual({})
  })

  it("set applies optimistic local write and marks dirty", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.set((d) => ({ ...d, theme: "dark" }))

    expect(store.state.data.get()).toEqual({ theme: "dark" })
    expect(store.state.dirty.get()).toBe(true)
  })

  it("set triggers background flush when online", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.set((d) => ({ ...d, theme: "dark" }))

    await vi.waitFor(() => {
      expect(pushFn).toHaveBeenCalled()
    })
  })

  it("set does not flush when offline", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.setOnline(false)
    store.set((d) => ({ ...d, theme: "dark" }))

    await new Promise((r) => setTimeout(r, 10))
    expect(pushFn).not.toHaveBeenCalled()
    expect(store.state.dirty.get()).toBe(true)
  })

  it("flush pushes data and clears dirty flag", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.setOnline(false)
    store.set((d) => ({ ...d, x: 1 }))
    store.setOnline(true)

    await vi.waitFor(() => {
      expect(store.state.dirty.get()).toBe(false)
    })
    expect(pushFn).toHaveBeenCalled()
  })

  it("flush sets error on failure but keeps data and dirty flag", async () => {
    const pushFn = vi.fn(async () => { throw new Error("server error") })
    const { store } = createTestStore({ push: pushFn })

    store.setOnline(false)
    store.set((d) => ({ ...d, important: true }))
    expect(store.state.dirty.get()).toBe(true)

    store.setOnline(true)

    await vi.waitFor(() => {
      expect(store.state.error.get()).toBe("server error")
    })
    expect(store.state.data.get()).toEqual({ important: true })
    expect(store.state.dirty.get()).toBe(true)
  })

  it("setOnline flushes dirty data when going online", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.setOnline(false)
    store.set((d) => ({ ...d, queued: true }))
    expect(pushFn).not.toHaveBeenCalled()

    store.setOnline(true)

    await vi.waitFor(() => {
      expect(pushFn).toHaveBeenCalled()
    })
  })

  it("set clears error state", async () => {
    const { store } = createTestStore({
      pull: async () => { throw new Error("pull failed") },
    })

    await store.pull()
    expect(store.state.error.get()).toBe("pull failed")

    store.set((d) => ({ ...d, fixed: true }))
    expect(store.state.error.get()).toBeNull()
  })

  it("set handles modifier errors gracefully", () => {
    const { store } = createTestStore()

    store.set(() => { throw new Error("modifier broke") })

    expect(store.state.error.get()).toBe("modifier broke")
    expect(store.state.data.get()).toEqual({})
    expect(store.state.dirty.get()).toBe(false)
  })

  it("state is reactive — observers see changes immediately", () => {
    const { store } = createTestStore()
    const snapshots: Record<string, unknown>[] = []

    store.state.data.onChange(({ value }) => snapshots.push({ ...value }))

    store.set((d) => ({ ...d, a: 1 }))
    store.set((d) => ({ ...d, b: 2 }))

    expect(snapshots).toContainEqual({ a: 1 })
    expect(snapshots).toContainEqual({ a: 1, b: 2 })
  })
})

describe("produce option (immer)", () => {
  function createImmerStore(clientOverrides?: Parameters<typeof mockClient>[0]) {
    const client = mockClient(clientOverrides)
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })
    return createStarfishObservable({ name: "immer-test", syncManager, produce })
  }

  it("supports draft-based mutations", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const store = createImmerStore({ push: pushFn })

    store.set((draft) => { draft.theme = "dark" })

    expect(store.state.data.get()).toEqual({ theme: "dark" })
    expect(store.state.dirty.get()).toBe(true)
  })

  it("still supports return-new-object pattern", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const store = createImmerStore({ push: pushFn })

    store.set((d) => ({ ...d, lang: "fr" }))

    expect(store.state.data.get()).toEqual({ lang: "fr" })
  })

  it("handles nested draft mutations", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const store = createImmerStore({ push: pushFn })

    store.set((d) => ({ ...d, prefs: { color: "red", size: 12 } }))
    store.set((draft) => {
      (draft.prefs as Record<string, unknown>).color = "blue"
    })

    expect(store.state.data.get()).toEqual({ prefs: { color: "blue", size: 12 } })
  })
})
