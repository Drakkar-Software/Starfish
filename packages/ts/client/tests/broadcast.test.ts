import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { createStore } from "zustand/vanilla"
import type { StarfishStore } from "../src/bindings/zustand.js"
import { setupBroadcastSync, setupCrossTabSync } from "../src/bindings/broadcast.js"

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
    // Deliver to other instances with the same name
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

function createMockStore(initial?: Partial<StarfishStore>): ReturnType<typeof createStore<StarfishStore>> {
  return createStore<StarfishStore>()((set) => ({
    data: {},
    syncing: false,
    online: true,
    dirty: false,
    error: null,
    pull: async () => {},
    set: () => {},
    flush: async () => {},
    setOnline: () => {},
    ...initial,
  }))
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

    // Simulate a data change in store1
    store1.setState({ data: { theme: "dark" }, dirty: true })

    // Store2 should have received the update
    expect(store2.getState().data).toEqual({ theme: "dark" })
    expect(store2.getState().dirty).toBe(true)
  })

  it("prevents echo loops", () => {
    const store1 = createMockStore()
    const store2 = createMockStore()

    setupBroadcastSync(store1, "echo-test")
    setupBroadcastSync(store2, "echo-test")

    // Track setState calls on store1
    const setStateSpy = vi.spyOn(store1, "setState")

    // Change store2 — should update store1 once
    store2.setState({ data: { x: 1 }, dirty: false })

    // store1.setState should have been called once (from broadcast), not recursively
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

    // Change something other than data/dirty
    store1.setState({ syncing: true })

    // Should not have broadcast to store2
    expect(setStateSpy).not.toHaveBeenCalled()
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
    // Remove BroadcastChannel and localStorage
    const origBC = globalThis.BroadcastChannel
    const origLS = globalThis.localStorage
    // @ts-expect-error - removing for test
    delete globalThis.BroadcastChannel
    // @ts-expect-error - removing for test
    delete globalThis.localStorage

    const store = createMockStore()
    const cleanup = setupCrossTabSync(store, "none")

    expect(cleanup).toBeTypeOf("function")
    cleanup() // should not throw

    globalThis.BroadcastChannel = origBC
    // @ts-expect-error - restoring for test
    globalThis.localStorage = origLS
  })
})
