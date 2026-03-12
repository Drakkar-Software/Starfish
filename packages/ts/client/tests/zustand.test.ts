import { describe, it, expect, vi, beforeEach } from "vitest"
import { produce } from "immer"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishStore } from "../src/bindings/zustand.js"
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

  const store = createStarfishStore({
    name: "test",
    syncManager,
    storage: false,
  })

  return { store, client, syncManager }
}

describe("createStarfishStore", () => {
  it("has correct initial state", () => {
    const { store } = createTestStore()
    const state = store.getState()

    expect(state.data).toEqual({})
    expect(state.syncing).toBe(false)
    expect(state.online).toBe(true)
    expect(state.dirty).toBe(false)
    expect(state.error).toBeNull()
  })

  it("pull fetches remote data into store", async () => {
    const { store } = createTestStore()

    await store.getState().pull()

    const state = store.getState()
    expect(state.data).toEqual({ key: "value" })
    expect(state.syncing).toBe(false)
    expect(state.error).toBeNull()
  })

  it("pull sets error on failure", async () => {
    const { store } = createTestStore({
      pull: async () => { throw new Error("network down") },
    })

    await store.getState().pull()

    const state = store.getState()
    expect(state.error).toBe("network down")
    expect(state.syncing).toBe(false)
    expect(state.data).toEqual({})
  })

  it("set applies optimistic local write and marks dirty", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.getState().set((d) => ({ ...d, theme: "dark" }))

    const state = store.getState()
    expect(state.data).toEqual({ theme: "dark" })
    expect(state.dirty).toBe(true)
  })

  it("set triggers background flush when online", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.getState().set((d) => ({ ...d, theme: "dark" }))

    // Wait for the async flush to complete
    await vi.waitFor(() => {
      expect(pushFn).toHaveBeenCalled()
    })
  })

  it("set does not flush when offline", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, theme: "dark" }))

    // Give it a tick to ensure no async call
    await new Promise((r) => setTimeout(r, 10))
    expect(pushFn).not.toHaveBeenCalled()
    expect(store.getState().dirty).toBe(true)
  })

  it("flush pushes data and clears dirty flag", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    // Go offline, write, then manually flush
    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, x: 1 }))
    store.getState().setOnline(true)

    await vi.waitFor(() => {
      expect(store.getState().dirty).toBe(false)
    })
    expect(pushFn).toHaveBeenCalled()
  })

  it("flush sets error on failure but keeps data", async () => {
    const pushFn = vi.fn(async () => { throw new Error("server error") })
    const { store } = createTestStore({ push: pushFn })

    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, important: true }))
    expect(store.getState().dirty).toBe(true)

    store.getState().setOnline(true)

    await vi.waitFor(() => {
      expect(store.getState().error).toBe("server error")
    })
    // Data and dirty flag preserved for retry
    expect(store.getState().data).toEqual({ important: true })
    expect(store.getState().dirty).toBe(true)
  })

  it("setOnline flushes dirty data when going online", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, queued: true }))

    expect(pushFn).not.toHaveBeenCalled()

    store.getState().setOnline(true)

    await vi.waitFor(() => {
      expect(pushFn).toHaveBeenCalled()
    })
  })

  it("set clears error state", async () => {
    const { store } = createTestStore({
      pull: async () => { throw new Error("pull failed") },
    })

    await store.getState().pull()
    expect(store.getState().error).toBe("pull failed")

    store.getState().set((d) => ({ ...d, fixed: true }))
    expect(store.getState().error).toBeNull()
  })

  it("set handles modifier errors gracefully", () => {
    const { store } = createTestStore()

    store.getState().set(() => { throw new Error("modifier broke") })

    const state = store.getState()
    expect(state.error).toBe("modifier broke")
    expect(state.data).toEqual({})
    expect(state.dirty).toBe(false)
  })

  it("subscribe reacts to state changes", async () => {
    const { store } = createTestStore()
    const values: unknown[] = []

    store.subscribe((state) => {
      values.push(state.data)
    })

    store.getState().set((d) => ({ ...d, a: 1 }))

    expect(values.length).toBeGreaterThanOrEqual(1)
    expect(values).toContainEqual({ a: 1 })
  })
})

describe("subscribeWithSelector", () => {
  it("subscribe with selector only fires on selected slice changes", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const client = mockClient({ push: pushFn })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const store = createStarfishStore({
      name: "selector-test",
      syncManager,
      storage: false,
    })

    const dataSnapshots: Record<string, unknown>[] = []

    // Subscribe to only the `data` slice
    store.subscribe(
      (state) => state.data,
      (data) => { dataSnapshots.push(data) },
    )

    // Change data — should fire
    store.getState().set((d) => ({ ...d, x: 1 }))
    expect(dataSnapshots).toContainEqual({ x: 1 })

    const countBeforeOnline = dataSnapshots.length

    // Change online status — should NOT fire the data listener
    store.getState().setOnline(false)
    expect(dataSnapshots.length).toBe(countBeforeOnline)
  })

  it("subscribe with equality function controls notifications", () => {
    const { store } = createTestStore()
    const calls: boolean[] = []

    // Subscribe to dirty flag with custom equality
    store.subscribe(
      (state) => state.dirty,
      (dirty) => { calls.push(dirty) },
      { equalityFn: Object.is },
    )

    // Set dirty to true (initial is false) — should fire
    store.getState().set((d) => ({ ...d, a: 1 }))
    expect(calls).toContain(true)
  })
})

describe("devtools", () => {
  it("creates store without error when devtools is true", () => {
    const client = mockClient()
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const store = createStarfishStore({
      name: "devtools-test",
      syncManager,
      storage: false,
      devtools: true,
    })

    expect(store.getState().data).toEqual({})
  })

  it("creates store with custom devtools options", () => {
    const client = mockClient()
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const store = createStarfishStore({
      name: "devtools-custom",
      syncManager,
      storage: false,
      devtools: { name: "My Custom Store", enabled: false },
    })

    expect(store.getState().data).toEqual({})
  })

  it("all actions still work with devtools enabled", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const client = mockClient({ push: pushFn })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const store = createStarfishStore({
      name: "devtools-actions",
      syncManager,
      storage: false,
      devtools: true,
    })

    // pull
    await store.getState().pull()
    expect(store.getState().data).toEqual({ key: "value" })

    // set + flush
    store.getState().set((d) => ({ ...d, extra: true }))
    await vi.waitFor(() => {
      expect(pushFn).toHaveBeenCalled()
    })
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

    const store = createStarfishStore({
      name: "immer-test",
      syncManager,
      storage: false,
      produce,
    })

    return { store, client, syncManager }
  }

  it("supports draft-based mutations", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createImmerStore({ push: pushFn })

    // Mutate draft — immer produces a new immutable object
    store.getState().set((draft) => { draft.theme = "dark" })

    expect(store.getState().data).toEqual({ theme: "dark" })
    expect(store.getState().dirty).toBe(true)
  })

  it("still supports return-new-object pattern", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createImmerStore({ push: pushFn })

    // Return new object — immer handles this too
    store.getState().set((d) => ({ ...d, lang: "fr" }))

    expect(store.getState().data).toEqual({ lang: "fr" })
  })

  it("handles nested draft mutations", () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createImmerStore({ push: pushFn })

    // Set initial nested data
    store.getState().set((d) => ({ ...d, prefs: { color: "red", size: 12 } }))

    // Mutate nested property via draft
    store.getState().set((draft) => {
      (draft.prefs as Record<string, unknown>).color = "blue"
    })

    expect(store.getState().data).toEqual({ prefs: { color: "blue", size: 12 } })
  })

  it("produce function is called for every set()", () => {
    const mockProduce = vi.fn((base, recipe) => {
      const result = recipe({ ...base })
      return result ?? base
    })

    const client = mockClient({ push: vi.fn(async () => ({ hash: "h1", timestamp: 100 })) })
    const syncManager = new SyncManager({
      client,
      pullPath: "/pull/test",
      pushPath: "/push/test",
    })

    const store = createStarfishStore({
      name: "mock-produce",
      syncManager,
      storage: false,
      produce: mockProduce,
    })

    store.getState().set((d) => ({ ...d, x: 1 }))
    expect(mockProduce).toHaveBeenCalledTimes(1)

    store.getState().set((d) => ({ ...d, y: 2 }))
    expect(mockProduce).toHaveBeenCalledTimes(2)
  })
})
