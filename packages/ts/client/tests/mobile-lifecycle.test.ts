import { describe, it, expect, vi, beforeEach } from "vitest"
import { StarfishClient } from "../src/client.js"
import { SyncManager } from "../src/sync.js"
import { createStarfishStore } from "../src/bindings/zustand.js"
import { createMobileLifecycle } from "../src/mobile-lifecycle.js"
import type { AppStateModule, NetInfoModule } from "../src/mobile-lifecycle.js"
import type { PullResponse, PushSuccess } from "../src/types.js"

// ── Helpers ───────────────────────────────────────────────────────────────────

function createTestStore() {
  const pullFn = vi.fn<(path: string, checkpoint?: number) => Promise<PullResponse>>(async () => ({
    data: {},
    hash: "h0",
    timestamp: 0,
  }))
  const pushFn = vi.fn<(path: string, data: Record<string, unknown>, baseHash: string | null, sig?: string) => Promise<PushSuccess>>(
    async () => ({ hash: "h1", timestamp: 100 }),
  )

  const client = { pull: pullFn, push: pushFn } as unknown as StarfishClient
  const syncManager = new SyncManager({ client, pullPath: "/pull/test", pushPath: "/push/test" })
  const store = createStarfishStore({ name: "test", syncManager, storage: false })
  return { store, pullFn, pushFn, syncManager }
}

function createMockAppState() {
  let listener: ((state: string) => void) | null = null
  const removeFn = vi.fn()
  const module: AppStateModule = {
    addEventListener: vi.fn((_type: string, fn: (state: string) => void) => {
      listener = fn
      return { remove: removeFn }
    }),
  }
  return {
    module,
    emit: (state: string) => listener?.(state),
    removeFn,
  }
}

function createMockNetInfo() {
  let listener: ((state: { isConnected: boolean | null }) => void) | null = null
  const unsubscribe = vi.fn()
  const module: NetInfoModule = {
    addEventListener: vi.fn((fn) => {
      listener = fn
      return unsubscribe
    }),
  }
  return {
    module,
    emit: (isConnected: boolean | null) => listener?.({ isConnected }),
    unsubscribe,
  }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("createMobileLifecycle", () => {
  it("flushes when app goes to background and store is dirty", () => {
    const { store } = createTestStore()
    const flushSpy = vi.spyOn(store.getState(), "flush").mockResolvedValue()
    // Set dirty=true directly without triggering auto-flush
    store.setState({ dirty: true })

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("background")

    expect(flushSpy).toHaveBeenCalled()
  })

  it("does not flush when app goes to background and store is not dirty", () => {
    const { store } = createTestStore()
    const flushSpy = vi.spyOn(store.getState(), "flush").mockResolvedValue()
    // Store starts clean (dirty=false)

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("background")

    expect(flushSpy).not.toHaveBeenCalled()
  })

  it("pulls when app returns to foreground while online and not syncing", () => {
    const { store } = createTestStore()
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue()
    store.getState().setOnline(true)

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("active")

    expect(pullSpy).toHaveBeenCalled()
  })

  it("does not pull when app returns to foreground while offline", () => {
    const { store } = createTestStore()
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue()
    store.getState().setOnline(false)

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("active")

    expect(pullSpy).not.toHaveBeenCalled()
  })

  it("does not pull when app returns to foreground while already syncing", () => {
    const { store } = createTestStore()
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue()
    // Directly set syncing=true in store state
    store.setState({ online: true, syncing: true })

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("active")

    expect(pullSpy).not.toHaveBeenCalled()
  })

  it("ignores 'inactive' and unknown AppState values", () => {
    const { store } = createTestStore()
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue()
    const flushSpy = vi.spyOn(store.getState(), "flush").mockResolvedValue()
    store.getState().setOnline(true)

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module })

    appState.emit("inactive")
    appState.emit("unknown")

    expect(pullSpy).not.toHaveBeenCalled()
    expect(flushSpy).not.toHaveBeenCalled()
  })

  it("sets store online when NetInfo reports connected", () => {
    const { store } = createTestStore()
    store.getState().setOnline(false)

    const appState = createMockAppState()
    const netInfo = createMockNetInfo()
    createMobileLifecycle(store, { appState: appState.module, netInfo: netInfo.module })

    netInfo.emit(true)

    expect(store.getState().online).toBe(true)
  })

  it("sets store offline when NetInfo reports disconnected", () => {
    const { store } = createTestStore()
    store.getState().setOnline(true)

    const appState = createMockAppState()
    const netInfo = createMockNetInfo()
    createMobileLifecycle(store, { appState: appState.module, netInfo: netInfo.module })

    netInfo.emit(false)

    expect(store.getState().online).toBe(false)
  })

  it("treats null isConnected as offline", () => {
    const { store } = createTestStore()
    store.getState().setOnline(true)

    const appState = createMockAppState()
    const netInfo = createMockNetInfo()
    createMobileLifecycle(store, { appState: appState.module, netInfo: netInfo.module })

    netInfo.emit(null)

    expect(store.getState().online).toBe(false)
  })

  it("cleanup removes AppState listener", () => {
    const { store } = createTestStore()
    const appState = createMockAppState()
    const cleanup = createMobileLifecycle(store, { appState: appState.module })

    cleanup()

    expect(appState.removeFn).toHaveBeenCalled()
  })

  it("cleanup unsubscribes NetInfo listener", () => {
    const { store } = createTestStore()
    const appState = createMockAppState()
    const netInfo = createMockNetInfo()
    const cleanup = createMobileLifecycle(store, { appState: appState.module, netInfo: netInfo.module })

    cleanup()

    expect(netInfo.unsubscribe).toHaveBeenCalled()
  })

  it("works without netInfo (no error, no listener registered)", () => {
    const { store } = createTestStore()
    const appState = createMockAppState()

    const cleanup = createMobileLifecycle(store, { appState: appState.module })
    expect(() => cleanup()).not.toThrow()
  })

  it("pullOnForeground: false disables pull on active", () => {
    const { store } = createTestStore()
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue()
    store.getState().setOnline(true)

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module }, { pullOnForeground: false })

    appState.emit("active")

    expect(pullSpy).not.toHaveBeenCalled()
  })

  it("flushOnBackground: false disables flush on background", () => {
    const { store } = createTestStore()
    const flushSpy = vi.spyOn(store.getState(), "flush").mockResolvedValue()
    // Set dirty=true directly without triggering auto-flush
    store.setState({ dirty: true })

    const appState = createMockAppState()
    createMobileLifecycle(store, { appState: appState.module }, { flushOnBackground: false })

    appState.emit("background")

    expect(flushSpy).not.toHaveBeenCalled()
  })
})
