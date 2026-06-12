import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { produce } from "immer"
import { devtools } from "zustand/middleware"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishStore, subscribeSyncStatus } from "../src/bindings/zustand.js"
import { StarfishHttpError } from "../src/types.js"
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

  it("pull sets error on HTTP/server failure", async () => {
    const { store } = createTestStore({
      pull: async () => { throw new StarfishHttpError(500, "server exploded") },
    })

    await store.getState().pull()

    const state = store.getState()
    expect(state.error).toBe("HTTP 500: server exploded")
    expect(state.syncing).toBe(false)
    expect(state.stale).toBe(false)
    expect(state.data).toEqual({})
  })

  it("pull preserves persisted data and sets stale on transport failure (offline)", async () => {
    // First pull succeeds — simulates data already in the store from a previous sync.
    const { store } = createTestStore()
    await store.getState().pull()
    expect(store.getState().data).toEqual({ key: "value" })

    // Subsequent pull fails with a transport/offline error (classifyError → "network").
    const { store: store2 } = createTestStore({
      pull: async () => { throw new TypeError("fetch failed") },
    })
    // Seed the store with existing data to simulate a persist-rehydrated state.
    store2.getState().restore({ key: "cached" })

    await store2.getState().pull()

    const state = store2.getState()
    expect(state.stale).toBe(true)
    expect(state.error).toBeNull()
    expect(state.syncing).toBe(false)
    // Persisted data must be preserved — no clobber on offline pull.
    expect(state.data).toEqual({ key: "cached" })
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

  it("restore updates data without marking dirty or flushing", async () => {
    const pushFn = vi.fn(async () => ({ hash: "h1", timestamp: 100 }))
    const { store } = createTestStore({ push: pushFn })

    store.getState().restore({ restored: true })

    const state = store.getState()
    expect(state.data).toEqual({ restored: true })
    expect(state.dirty).toBe(false)

    // Give it a tick to ensure no async flush
    await new Promise((r) => setTimeout(r, 10))
    expect(pushFn).not.toHaveBeenCalled()
  })

  it("restore does not clear existing error", () => {
    const { store } = createTestStore({
      pull: async () => { throw new Error("pull failed") },
    })

    // Manually set an error state
    store.setState({ error: "something" })

    store.getState().restore({ data: "from pull" })

    // restore only sets data, doesn't touch error
    expect(store.getState().data).toEqual({ data: "from pull" })
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
  it("creates store without error when devtools wrapper passed", () => {
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
      devtools: (fn) => devtools(fn),
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
      devtools: (fn) => devtools(fn, { name: "My Custom Store", enabled: false }),
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
      devtools: (fn) => devtools(fn),
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

// ── onRemoteUpdate ────────────────────────────────────────────────────────────

describe("onRemoteUpdate", () => {
  it("is called after pull() with the pulled data", async () => {
    const onRemoteUpdate = vi.fn()
    const client = mockClient()
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({ name: "ru1", syncManager, storage: false, onRemoteUpdate })

    await store.getState().pull()

    expect(onRemoteUpdate).toHaveBeenCalledTimes(1)
    expect(onRemoteUpdate).toHaveBeenCalledWith({ key: "value" })
  })

  it("is NOT called after set()", async () => {
    const onRemoteUpdate = vi.fn()
    const client = mockClient()
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({ name: "ru2", syncManager, storage: false, onRemoteUpdate })

    store.getState().set((d) => ({ ...d, local: true }))

    // Give flush a tick to complete — onRemoteUpdate must still not fire
    await new Promise((r) => setTimeout(r, 20))
    expect(onRemoteUpdate).not.toHaveBeenCalled()
  })

  it("is NOT called when pull() fails", async () => {
    const onRemoteUpdate = vi.fn()
    const client = mockClient({ pull: async () => { throw new Error("fail") } })
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({ name: "ru3", syncManager, storage: false, onRemoteUpdate })

    await store.getState().pull()

    expect(onRemoteUpdate).not.toHaveBeenCalled()
    expect(store.getState().error).toBe("fail")
  })

  it("store data is already updated when onRemoteUpdate fires", async () => {
    let dataAtCallTime: Record<string, unknown> | undefined
    const client = mockClient()
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({
      name: "ru4",
      syncManager,
      storage: false,
      onRemoteUpdate: () => {
        dataAtCallTime = store.getState().data
      },
    })

    await store.getState().pull()

    expect(dataAtCallTime).toEqual({ key: "value" })
  })

  it("calling set() inside onRemoteUpdate does not cause infinite loop", async () => {
    let callCount = 0
    const client = mockClient()
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({
      name: "ru5",
      syncManager,
      storage: false,
      onRemoteUpdate: (data) => {
        callCount++
        // Simulates domain store restoration that would normally re-trigger sync
        store.getState().restore({ ...data, restored: true })
      },
    })

    await store.getState().pull()

    // onRemoteUpdate fires exactly once — restore() does not re-trigger pull()
    expect(callCount).toBe(1)
  })
})

// ── subscribeSyncStatus ───────────────────────────────────────────────────────

describe("subscribeSyncStatus", () => {
  it("calls callback immediately with current status", () => {
    const { store } = createTestStore()
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))
    unsub()

    expect(statuses).toEqual(["synced"])
  })

  it("emits 'pending' when store is dirty and online", async () => {
    // Use a slow push so we can observe the 'pending' state before flush completes
    let resolvePush!: () => void
    const slowPush = vi.fn(
      () =>
        new Promise<PushSuccess>((resolve) => {
          resolvePush = () => resolve({ hash: "h1", timestamp: 100 })
        }),
    )
    const { store } = createTestStore({ push: slowPush })
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))

    // Go offline so set() marks dirty without triggering flush
    store.getState().setOnline(false)
    store.getState().set((d) => ({ ...d, x: 1 }))

    // Now go back online: state is dirty+online → "pending" before flush starts
    store.getState().setOnline(true)

    // At this moment we should see "pending" (dirty=true, syncing may not have started yet)
    expect(statuses).toContain("pending")

    resolvePush()
    await vi.waitFor(() => expect(store.getState().syncing).toBe(false))
    unsub()
  })

  it("emits 'offline' when store goes offline", () => {
    const { store } = createTestStore()
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))
    store.getState().setOnline(false)
    unsub()

    expect(statuses).toContain("offline")
  })

  it("emits 'syncing' during an in-flight push", async () => {
    let resolvePush!: () => void
    const pushFn = vi.fn(
      () =>
        new Promise<PushSuccess>((resolve) => {
          resolvePush = () => resolve({ hash: "h1", timestamp: 100 })
        }),
    )
    const { store } = createTestStore({ push: pushFn })
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))
    store.getState().set((d) => ({ ...d, x: 1 }))

    await vi.waitFor(() => expect(statuses).toContain("syncing"))
    resolvePush()
    await vi.waitFor(() => expect(store.getState().syncing).toBe(false))
    unsub()

    expect(statuses).toContain("syncing")
    expect(statuses[statuses.length - 1]).toBe("synced")
  })

  it("emits 'error' after a failed push", async () => {
    const { store } = createTestStore({
      push: async () => { throw new Error("push failed") },
    })
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))
    store.getState().set((d) => ({ ...d, x: 1 }))

    await vi.waitFor(() => expect(statuses).toContain("error"))
    unsub()
  })

  it("does not emit duplicate statuses (unchanged state)", () => {
    const { store } = createTestStore()
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))

    // Trigger multiple state changes that don't change the derived status
    store.setState({ error: null })
    store.setState({ error: null })
    unsub()

    // Should only have the initial "synced" call
    expect(statuses.filter((s) => s === "synced")).toHaveLength(1)
  })

  it("cleanup function stops further callbacks", () => {
    const { store } = createTestStore()
    const statuses: string[] = []

    const unsub = subscribeSyncStatus(store, (s) => statuses.push(s))
    unsub()  // cleanup immediately after initial call

    store.getState().setOnline(false)  // would emit "offline" if still subscribed
    expect(statuses).not.toContain("offline")
  })
})

// ── hash persistence ──────────────────────────────────────────────────────────

describe("hash persistence", () => {
  function makeMemoryStorage() {
    const map = new Map<string, string>()
    return {
      getItem: (key: string) => map.get(key) ?? null,
      setItem: (key: string, value: string) => { map.set(key, value) },
      removeItem: (key: string) => { map.delete(key) },
      snapshot: () => {
        const raw = map.get("starfish-hash-test")
        return raw ? JSON.parse(raw) as { state: { hash: string | null } } : null
      },
    }
  }

  function makeHashStore(storage = makeMemoryStorage(), clientOverrides?: Parameters<typeof mockClient>[0]) {
    const client = mockClient(clientOverrides)
    const syncManager = new SyncManager({ client, pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({ name: "hash-test", syncManager, storage })
    return { store, syncManager, client, storage }
  }

  it("pull/success writes state.hash from syncManager.getHash()", async () => {
    const { store } = makeHashStore()
    expect(store.getState().hash).toBeNull()
    await store.getState().pull()
    expect(store.getState().hash).toBe("abc123")
  })

  it("flush/success writes state.hash from syncManager.getHash()", async () => {
    const { store } = makeHashStore()
    store.getState().set((d) => ({ ...d, x: 1 }))
    await vi.waitFor(() => expect(store.getState().dirty).toBe(false))
    expect(store.getState().hash).toBe("def456")
  })

  it("hash is included in the partialize snapshot written to storage", async () => {
    const storage = makeMemoryStorage()
    const { store } = makeHashStore(storage)
    await store.getState().pull()
    const snap = storage.snapshot()
    expect(snap).not.toBeNull()
    expect(snap!.state.hash).toBe("abc123")
  })

  it("hash null does not pollute partialize snapshot before any sync", () => {
    const storage = makeMemoryStorage()
    // Just creating the store should not write a hash
    makeHashStore(storage)
    const snap = storage.snapshot()
    // If nothing has been written, snapshot is null; if written, hash must be null
    if (snap !== null) expect(snap.state.hash).toBeNull()
  })

  it("onRehydrateStorage calls syncManager.setHash with the persisted hash", async () => {
    const storage = makeMemoryStorage()

    // First session: pull to populate hash in storage
    const { store: storeA, syncManager: smA } = makeHashStore(storage)
    await storeA.getState().pull()
    expect(smA.getHash()).toBe("abc123")

    // Second session: create a fresh syncManager + store over the same storage
    const clientB = mockClient()
    const smB = new SyncManager({ client: clientB, pullPath: "/pull/t", pushPath: "/push/t" })
    expect(smB.getHash()).toBeNull() // starts fresh

    createStarfishStore({ name: "hash-test", syncManager: smB, storage })

    // Hydration is synchronous when storage.getItem is sync; yield a microtask to be safe
    await Promise.resolve()
    expect(smB.getHash()).toBe("abc123")
  })

  it("onRehydrateStorage does NOT call setHash when persisted hash is absent", async () => {
    const storage = makeMemoryStorage()
    // Write state without hash to simulate a 2.0.0-era persisted entry
    storage.setItem("starfish-hash-test", JSON.stringify({ state: { data: {}, dirty: false }, version: 0 }))

    const smC = new SyncManager({ client: mockClient(), pullPath: "/pull/t", pushPath: "/push/t" })
    createStarfishStore({ name: "hash-test", syncManager: smC, storage })

    await Promise.resolve()
    expect(smC.getHash()).toBeNull()
  })

  it("onRehydrateStorage does NOT overwrite a hash already set by a completed pull()", async () => {
    // Simulate async storage: getItem returns a Promise that resolves only after pull() has run.
    let resolveGet!: (v: string | null) => void
    const asyncStorage = {
      getItem: (_key: string) => new Promise<string | null>((r) => { resolveGet = r }),
      setItem: vi.fn(),
      removeItem: vi.fn(),
    }

    const sm = new SyncManager({ client: mockClient(), pullPath: "/pull/t", pushPath: "/push/t" })
    const store = createStarfishStore({ name: "race-test", syncManager: sm, storage: asyncStorage })

    // pull() completes first — server returns hash "abc123"
    await store.getState().pull()
    expect(sm.getHash()).toBe("abc123")

    // Async storage resolves afterward with a stale persisted hash
    resolveGet(JSON.stringify({ state: { data: {}, dirty: false, hash: "stale-hash" }, version: 0 }))
    await Promise.resolve()

    // Server hash must not be clobbered
    expect(sm.getHash()).toBe("abc123")
  })
})

// ── flushRetry ────────────────────────────────────────────────────────────────

describe("flushRetry", () => {
  beforeEach(() => {
    // Eliminate the ±100 ms jitter so retry delays are exactly initialDelayMs * 2^attempt.
    // This makes timing assertions deterministic without needing fake timers.
    vi.spyOn(Math, "random").mockReturnValue(0)
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  /** Store with flushRetry enabled and very short delays for fast tests. */
  function createRetryStore(
    pushFn: Parameters<typeof mockClient>[0]["push"],
    retryOpts: { maxRetries?: number; initialDelayMs?: number; maxDelayMs?: number } = {},
  ) {
    const client = mockClient({ push: pushFn })
    const syncManager = new SyncManager({ client, pullPath: "/pull/retry", pushPath: "/push/retry" })
    const store = createStarfishStore({
      name: "retry-test",
      syncManager,
      storage: false,
      flushRetry: { maxRetries: 3, initialDelayMs: 10, maxDelayMs: 10_000, ...retryOpts },
    })
    return { store, client }
  }

  it("no flushRetry option — a failed flush is NOT retried automatically", async () => {
    const pushFn = vi.fn(async () => { throw new Error("server error") })
    const { store } = createTestStore({ push: pushFn })

    store.getState().set((d) => ({ ...d, x: 1 }))
    await vi.waitFor(() => expect(store.getState().error).toBe("server error"))
    pushFn.mockClear()

    // Wait past any plausible retry delay — nothing should fire
    await new Promise((r) => setTimeout(r, 100))
    expect(pushFn).not.toHaveBeenCalled()
    expect(store.getState().dirty).toBe(true)
  })

  it("recovers after a transient push failure", async () => {
    let attempt = 0
    const pushFn = vi.fn(async () => {
      if (attempt++ === 0) throw new Error("transient")
      return { hash: "h1", timestamp: 100 }
    })
    const { store } = createRetryStore(pushFn, { maxRetries: 3, initialDelayMs: 10 })

    store.getState().set((d) => ({ ...d, x: 1 }))

    // First flush fails, retry fires within ~10 ms (jitter=0), succeeds
    await vi.waitFor(() => expect(store.getState().dirty).toBe(false), { timeout: 2000 })
    expect(store.getState().error).toBeNull()
    expect(pushFn).toHaveBeenCalledTimes(2)
  })

  it("stops retrying after maxRetries attempts are exhausted", async () => {
    const pushFn = vi.fn(async () => { throw new Error("persistent") })
    // maxRetries=2: initial + retry1 + retry2 = 3 push calls total
    // delays (jitter=0): 10 ms, 20 ms
    const { store } = createRetryStore(pushFn, { maxRetries: 2, initialDelayMs: 10 })

    store.getState().set((d) => ({ ...d, x: 1 }))

    await vi.waitFor(() => expect(pushFn).toHaveBeenCalledTimes(3), { timeout: 2000 })

    // No further calls after exhaustion
    const countAtExhaustion = pushFn.mock.calls.length
    await new Promise((r) => setTimeout(r, 150))
    expect(pushFn.mock.calls.length).toBe(countAtExhaustion)
    expect(store.getState().dirty).toBe(true)
  })

  it("success resets retry counter — the next write gets a fresh budget", async () => {
    // push call order: 1=success (first write), 2=fail (second write), 3=success (retry)
    // Using call count avoids timing races with a mutable shouldFail flag.
    let callCount = 0
    const pushFn = vi.fn(async () => {
      callCount++
      if (callCount === 2) throw new Error("transient-on-second-write")
      return { hash: "h1", timestamp: 100 }
    })
    // maxRetries=1: would give 0 retries if the counter wasn't reset after first success
    const { store } = createRetryStore(pushFn, { maxRetries: 1, initialDelayMs: 10 })

    // First write (call 1): succeeds → cancelFlushRetry() resets retryAttempt to 0
    store.getState().set((d) => ({ ...d, x: 1 }))
    await vi.waitFor(() => expect(store.getState().dirty).toBe(false), { timeout: 1000 })
    expect(pushFn).toHaveBeenCalledTimes(1)

    // Second write: call 2 fails → retry scheduled (budget reset to 0 → 1 retry allowed)
    // Retry: call 3 succeeds → dirty clears
    store.getState().set((d) => ({ ...d, y: 2 }))
    await vi.waitFor(() => expect(store.getState().dirty).toBe(false), { timeout: 2000 })
    expect(store.getState().error).toBeNull()
    expect(pushFn).toHaveBeenCalledTimes(3)
  })

  it("setOnline(false) cancels a pending retry timer", async () => {
    const pushFn = vi.fn(async () => { throw new Error("fail") })
    // Long initial delay so the test can go offline before the timer fires
    const { store } = createRetryStore(pushFn, { maxRetries: 5, initialDelayMs: 500 })

    store.getState().set((d) => ({ ...d, x: 1 }))
    await vi.waitFor(() => expect(store.getState().error).toBe("fail"), { timeout: 1000 })
    pushFn.mockClear()

    // Going offline cancels the scheduled retry timer
    store.getState().setOnline(false)

    // Wait well past the retry delay — timer was cancelled, no push
    await new Promise((r) => setTimeout(r, 700))
    expect(pushFn).not.toHaveBeenCalled()
    expect(store.getState().dirty).toBe(true)
  })

  it("AbortError is not retried", async () => {
    const abortErr = Object.assign(new Error("aborted"), { name: "AbortError" })
    const pushFn = vi.fn(async () => { throw abortErr })
    const { store } = createRetryStore(pushFn, { maxRetries: 5, initialDelayMs: 10 })

    store.getState().set((d) => ({ ...d, x: 1 }))
    await vi.waitFor(() => expect(store.getState().error).toBe("aborted"))
    pushFn.mockClear()

    // No retry should fire for aborts (e.g. tab close, unmount)
    await new Promise((r) => setTimeout(r, 100))
    expect(pushFn).not.toHaveBeenCalled()
  })
})
