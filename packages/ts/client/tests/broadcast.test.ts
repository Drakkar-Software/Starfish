import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import type { BroadcastableStore } from "../src/broadcast.js"
import { setupBroadcastSync, setupStorageFallback, setupCrossTabSync } from "../src/broadcast.js"

type Listener = (event: MessageEvent) => void

class MockBroadcastChannel {
  static instances: MockBroadcastChannel[] = []
  name: string
  onmessage: Listener | null = null
  closed = false

  constructor(name: string) {
    this.name = name
    MockBroadcastChannel.instances.push(this)
  }

  postMessage(data: unknown) {
    for (const inst of MockBroadcastChannel.instances) {
      if (inst !== this && inst.name === this.name && !inst.closed && inst.onmessage) {
        inst.onmessage(new MessageEvent("message", { data }))
      }
    }
  }

  close() {
    this.closed = true
    MockBroadcastChannel.instances = MockBroadcastChannel.instances.filter((i) => i !== this)
  }
}

/** Framework-agnostic mock store implementing BroadcastableStore */
function createMockStore(initial?: Partial<{ data: Record<string, unknown>; dirty: boolean }>): BroadcastableStore {
  let state = {
    data: initial?.data ?? {} as Record<string, unknown>,
    dirty: initial?.dirty ?? false,
  }
  const listeners = new Set<(s: typeof state, prev: typeof state) => void>()

  return {
    getState: () => state,
    setState: (partial) => {
      const prev = state
      state = { ...state, ...partial }
      for (const fn of listeners) fn(state, prev)
    },
    subscribe: (listener) => {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
  }
}

beforeEach(() => {
  MockBroadcastChannel.instances = []
  vi.stubGlobal("BroadcastChannel", MockBroadcastChannel)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("setupBroadcastSync", () => {
  it("broadcasts state changes to other tabs", () => {
    const store1 = createMockStore()
    const store2 = createMockStore()

    setupBroadcastSync(store1, "test")
    setupBroadcastSync(store2, "test")

    store1.setState({ data: { theme: "dark" }, dirty: true })

    expect(store2.getState().data).toEqual({ theme: "dark" })
    expect(store2.getState().dirty).toBe(true)
  })

  it("prevents echo loops", () => {
    const store1 = createMockStore()
    const store2 = createMockStore()

    setupBroadcastSync(store1, "echo-test")
    setupBroadcastSync(store2, "echo-test")

    const setStateSpy = vi.spyOn(store1, "setState")

    store2.setState({ data: { x: 1 }, dirty: false })

    const broadcastCalls = setStateSpy.mock.calls.filter(
      (call) => call[0] && typeof call[0] === "object" && "data" in (call[0] as object),
    )
    expect(broadcastCalls.length).toBe(1)
  })

  it("cleanup closes channel and stops listening", () => {
    const store = createMockStore()
    const cleanup = setupBroadcastSync(store, "cleanup-test")

    expect(MockBroadcastChannel.instances.length).toBe(1)
    cleanup()
    expect(MockBroadcastChannel.instances.length).toBe(0)
  })

  it("does not broadcast when data has not changed", () => {
    const store1 = createMockStore()
    const store2 = createMockStore()

    setupBroadcastSync(store1, "no-change")
    setupBroadcastSync(store2, "no-change")

    const setStateSpy = vi.spyOn(store2, "setState")

    // setState with same data reference — should not broadcast
    const sameData = store1.getState().data
    store1.setState({ data: sameData, dirty: false })

    expect(setStateSpy).not.toHaveBeenCalled()
  })
})

describe("setupStorageFallback", () => {
  let storage: Record<string, string>
  let storageListeners: Array<(e: StorageEvent) => void>

  beforeEach(() => {
    vi.unstubAllGlobals()
    storage = {}
    storageListeners = []

    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage[key] ?? null,
      setItem: (key: string, value: string) => { storage[key] = value },
    })

    // Mock addEventListener/removeEventListener for storage events
    const origAdd = globalThis.addEventListener
    const origRemove = globalThis.removeEventListener
    vi.stubGlobal("addEventListener", (type: string, fn: EventListener) => {
      if (type === "storage") storageListeners.push(fn as (e: StorageEvent) => void)
      else origAdd(type, fn)
    })
    vi.stubGlobal("removeEventListener", (type: string, fn: EventListener) => {
      if (type === "storage") storageListeners = storageListeners.filter((l) => l !== fn)
      else origRemove(type, fn)
    })

    // Remove BroadcastChannel so setupCrossTabSync uses storage fallback
    // @ts-expect-error - removing for test
    delete globalThis.BroadcastChannel
  })

  it("writes store changes to localStorage", () => {
    const store = createMockStore()
    setupStorageFallback(store, "test")

    store.setState({ data: { theme: "dark" }, dirty: false })

    const stored = JSON.parse(storage["starfish-broadcast-test"])
    expect(stored.data).toEqual({ theme: "dark" })
  })

  it("receives storage events from other tabs", () => {
    const store = createMockStore()
    setupStorageFallback(store, "test")

    // Simulate storage event from another tab (plain object, no StorageEvent constructor needed)
    const event = { key: "starfish-broadcast-test", newValue: JSON.stringify({ data: { from: "other-tab" }, dirty: true }) }
    for (const fn of storageListeners) fn(event as StorageEvent)

    expect(store.getState().data).toEqual({ from: "other-tab" })
    expect(store.getState().dirty).toBe(true)
  })

  it("ignores corrupt JSON in storage events", () => {
    const store = createMockStore({ data: { original: true } })
    setupStorageFallback(store, "test")

    const event = { key: "starfish-broadcast-test", newValue: "not valid json" }
    for (const fn of storageListeners) fn(event as StorageEvent)

    expect(store.getState().data).toEqual({ original: true })
  })

  it("cleanup removes storage listener", () => {
    const store = createMockStore()
    const cleanup = setupStorageFallback(store, "test")

    expect(storageListeners.length).toBe(1)
    cleanup()
    expect(storageListeners.length).toBe(0)
  })
})

describe("setupCrossTabSync", () => {
  it("uses BroadcastChannel when available", () => {
    const store = createMockStore()
    const cleanup = setupCrossTabSync(store, "auto")

    expect(MockBroadcastChannel.instances.length).toBe(1)
    cleanup()
  })

  it("returns noop cleanup when no mechanism is available", () => {
    vi.unstubAllGlobals()
    const origBC = globalThis.BroadcastChannel
    const origLS = globalThis.localStorage
    // @ts-expect-error - removing for test
    delete globalThis.BroadcastChannel
    // @ts-expect-error - removing for test
    delete globalThis.localStorage

    const store = createMockStore()
    const cleanup = setupCrossTabSync(store, "none")

    expect(cleanup).toBeTypeOf("function")
    cleanup()

    globalThis.BroadcastChannel = origBC
    // @ts-expect-error - restoring for test
    globalThis.localStorage = origLS
  })
})
