import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishStore } from "../src/bindings/zustand.js"
import { createDebouncedSync } from "../src/debounced-sync.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

beforeEach(() => {
  vi.useFakeTimers()
})
afterEach(() => {
  vi.useRealTimers()
})

function makePushFn() {
  return vi.fn<(path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>>(
    async () => ({ hash: "h1", timestamp: 100 }),
  )
}

function createTestStore(pushFn = makePushFn()) {
  const client = {
    pull: vi.fn<(path: string, checkpoint?: number) => Promise<PullResponse>>(async () => ({
      data: {},
      hash: "h0",
      timestamp: 0,
    })),
    push: pushFn,
  } as unknown as StarfishClient

  const syncManager = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
  const store = createStarfishStore({ name: "test", syncManager, storage: false })
  return { store, pushFn }
}

describe("createDebouncedSync", () => {
  it("does not push immediately after notify()", () => {
    const { store, pushFn } = createTestStore()
    const { notify } = createDebouncedSync(store)

    notify()
    expect(pushFn).not.toHaveBeenCalled()
  })

  it("pushes after the debounce delay", async () => {
    const { store, pushFn } = createTestStore()
    store.getState().restore({ items: [1, 2, 3] })
    const { notify } = createDebouncedSync(store, { delayMs: 1000 })

    notify()
    await vi.advanceTimersByTimeAsync(1000)

    expect(pushFn).toHaveBeenCalledTimes(1)
  })

  it("resets timer on repeated notify() calls", async () => {
    const { store, pushFn } = createTestStore()
    const { notify } = createDebouncedSync(store, { delayMs: 1000 })

    notify()
    await vi.advanceTimersByTimeAsync(500)
    notify()  // reset timer
    await vi.advanceTimersByTimeAsync(500)  // only 500ms since last notify
    expect(pushFn).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(500)  // now 1000ms since last notify
    expect(pushFn).toHaveBeenCalledTimes(1)
  })

  it("cancel() prevents pending push", async () => {
    const { store, pushFn } = createTestStore()
    const { notify, cancel } = createDebouncedSync(store, { delayMs: 1000 })

    notify()
    cancel()
    await vi.advanceTimersByTimeAsync(2000)

    expect(pushFn).not.toHaveBeenCalled()
  })

  it("uses serialize() to build the sync document", async () => {
    const { store, pushFn } = createTestStore()
    const serialize = vi.fn(() => ({ custom: "doc" }))
    const { notify } = createDebouncedSync(store, { delayMs: 100, serialize })

    notify()
    await vi.advanceTimersByTimeAsync(100)

    expect(serialize).toHaveBeenCalledTimes(1)
    expect(pushFn).toHaveBeenCalledWith(
      expect.any(String),
      { custom: "doc" },
      null,   // baseHash is null before first push
      undefined,
    )
  })

  it("calls onSizeWarning when payload exceeds warnBytes", async () => {
    const { store } = createTestStore()
    // Put a large blob in the store
    const bigData = { blob: "x".repeat(2000) }
    store.getState().restore(bigData)

    const onSizeWarning = vi.fn()
    const { notify } = createDebouncedSync(store, {
      delayMs: 100,
      warnBytes: 100,  // very low threshold to trigger warning
      maxBytes: Infinity,
      onSizeWarning,
    })

    notify()
    await vi.advanceTimersByTimeAsync(100)

    expect(onSizeWarning).toHaveBeenCalledWith(expect.any(Number))
    const [calledWith] = onSizeWarning.mock.calls[0] as [number]
    expect(calledWith).toBeGreaterThan(100)
  })

  it("calls onSizeExceeded and blocks push when payload exceeds maxBytes", async () => {
    const { store, pushFn } = createTestStore()
    const bigData = { blob: "x".repeat(2000) }
    store.getState().restore(bigData)

    const onSizeExceeded = vi.fn()
    const { notify } = createDebouncedSync(store, {
      delayMs: 100,
      maxBytes: 100,  // tiny threshold
      onSizeExceeded,
    })

    notify()
    await vi.advanceTimersByTimeAsync(100)

    expect(onSizeExceeded).toHaveBeenCalledWith(expect.any(Number))
    expect(pushFn).not.toHaveBeenCalled()
  })

  it("prints console.error when maxBytes exceeded and no onSizeExceeded provided", async () => {
    const { store } = createTestStore()
    store.getState().restore({ blob: "x".repeat(2000) })

    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {})
    const { notify } = createDebouncedSync(store, { delayMs: 100, maxBytes: 100 })

    notify()
    await vi.advanceTimersByTimeAsync(100)

    expect(consoleError).toHaveBeenCalledWith(expect.stringContaining("Push blocked"))
    consoleError.mockRestore()
  })

  it("defaults to 2000ms debounce delay", async () => {
    const { store, pushFn } = createTestStore()
    const { notify } = createDebouncedSync(store)

    notify()
    await vi.advanceTimersByTimeAsync(1999)
    expect(pushFn).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1)
    expect(pushFn).toHaveBeenCalledTimes(1)
  })
})
