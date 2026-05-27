import { describe, it, expect, vi } from "vitest"
import { StarfishClient } from "../src/client.js"
import { AppendLogCursor, type AppendElement } from "../src/append-log.js"
import {
  createStarfishLog,
  deriveLogStatus,
  subscribeLogStatus,
} from "../src/bindings/zustand.js"
import { createStarfishLogObservable } from "../src/bindings/legend.js"
import { createAppendLogMobileLifecycle } from "../src/mobile-lifecycle.js"
import type { AppStateModule, NetInfoModule } from "../src/mobile-lifecycle.js"

/** Fake client whose append-pull returns each queued batch in turn. */
function logClient(...batches: AppendElement[][]): StarfishClient {
  const pull = vi.fn()
  if (batches.length === 0) pull.mockResolvedValue([])
  for (const b of batches) pull.mockResolvedValueOnce(b)
  return { pull } as unknown as StarfishClient
}

function cursorWith(client: StarfishClient, initialItems?: AppendElement[]) {
  return new AppendLogCursor({ client, pullPath: "/pull/events", initialItems })
}

// ── Zustand log binding ──────────────────────────────────────────────

describe("createStarfishLog (Zustand)", () => {
  it("cold start has empty initial state", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    const s = store.getState()
    expect(s.items).toEqual([])
    expect(s.loading).toBe(false)
    expect(s.online).toBe(true)
    expect(s.error).toBeNull()
    expect(s.checkpoint).toBe(0)
  })

  it("warm start seeds items + checkpoint from the cursor", () => {
    const cursor = cursorWith(logClient(), [{ ts: 100, data: { a: 1 } }])
    const store = createStarfishLog({ cursor })
    expect(store.getState().items).toEqual([{ ts: 100, data: { a: 1 } }])
    expect(store.getState().checkpoint).toBe(100)
  })

  it("pull appends the new batch and advances the checkpoint", async () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient([{ ts: 1, data: { x: 1 } }, { ts: 2, data: { y: 2 } }])) })
    const batch = await store.getState().pull()
    expect(batch).toEqual([{ ts: 1, data: { x: 1 } }, { ts: 2, data: { y: 2 } }])
    expect(store.getState().items).toEqual(batch)
    expect(store.getState().checkpoint).toBe(2)
    expect(store.getState().loading).toBe(false)
  })

  it("captures a pull error into state.error", async () => {
    const client = { pull: vi.fn(async () => { throw new Error("network down") }) } as unknown as StarfishClient
    const store = createStarfishLog({ cursor: cursorWith(client) })
    const batch = await store.getState().pull()
    expect(batch).toEqual([])
    expect(store.getState().error).toBe("network down")
    expect(store.getState().loading).toBe(false)
  })

  it("setOnline updates connectivity and deriveLogStatus", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    expect(deriveLogStatus(store.getState())).toBe("idle")
    store.getState().setOnline(false)
    expect(store.getState().online).toBe(false)
    expect(deriveLogStatus(store.getState())).toBe("offline")
  })

  it("subscribeLogStatus emits the initial status and on change", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    const seen: string[] = []
    const unsub = subscribeLogStatus(store, (s) => seen.push(s))
    store.getState().setOnline(false)
    unsub()
    store.getState().setOnline(true) // ignored after unsub
    expect(seen).toEqual(["idle", "offline"])
  })

  it("pull is a no-op while one is already in flight", async () => {
    const cursor = cursorWith(logClient([{ ts: 1, data: { x: 1 } }]))
    const pullSpy = vi.spyOn(cursor, "pull")
    const store = createStarfishLog({ cursor })
    store.setState({ loading: true }) // simulate an in-flight pull
    expect(await store.getState().pull()).toEqual([])
    expect(pullSpy).not.toHaveBeenCalled()
  })
})

// ── Legend log binding ───────────────────────────────────────────────

describe("createStarfishLogObservable (Legend)", () => {
  it("seeds from the cursor and appends on pull", async () => {
    const cursor = cursorWith(logClient([{ ts: 5, data: { n: 1 } }]), [{ ts: 1, data: { a: 0 } }])
    const store = createStarfishLogObservable({ cursor })
    expect(store.state.items.get()).toEqual([{ ts: 1, data: { a: 0 } }])
    expect(store.state.checkpoint.get()).toBe(1)

    const batch = await store.pull()
    expect(batch).toEqual([{ ts: 5, data: { n: 1 } }])
    expect(store.state.items.get()).toEqual([{ ts: 1, data: { a: 0 } }, { ts: 5, data: { n: 1 } }])
    expect(store.state.checkpoint.get()).toBe(5)
    expect(store.state.loading.get()).toBe(false)
  })

  it("captures a pull error", async () => {
    const client = { pull: vi.fn(async () => { throw new Error("boom") }) } as unknown as StarfishClient
    const store = createStarfishLogObservable({ cursor: cursorWith(client) })
    await store.pull()
    expect(store.state.error.get()).toBe("boom")
    expect(store.state.loading.get()).toBe(false)
  })

  it("setOnline updates the observable", () => {
    const store = createStarfishLogObservable({ cursor: cursorWith(logClient()) })
    store.setOnline(false)
    expect(store.state.online.get()).toBe(false)
  })

  it("pull is a no-op while one is already in flight", async () => {
    const cursor = cursorWith(logClient([{ ts: 1, data: { x: 1 } }]))
    const pullSpy = vi.spyOn(cursor, "pull")
    const store = createStarfishLogObservable({ cursor })
    store.state.loading.set(true) // simulate an in-flight pull
    expect(await store.pull()).toEqual([])
    expect(pullSpy).not.toHaveBeenCalled()
  })
})

// ── Mobile lifecycle ─────────────────────────────────────────────────

function mockAppState() {
  let listener: ((state: string) => void) | null = null
  const removeFn = vi.fn()
  const module: AppStateModule = {
    addEventListener: vi.fn((_type: string, fn: (state: string) => void) => {
      listener = fn
      return { remove: removeFn }
    }),
  }
  return { module, emit: (state: string) => listener?.(state), removeFn }
}

function mockNetInfo() {
  let listener: ((state: { isConnected: boolean | null }) => void) | null = null
  const unsubscribe = vi.fn()
  const module: NetInfoModule = {
    addEventListener: vi.fn((fn) => { listener = fn; return unsubscribe }),
  }
  return { module, emit: (isConnected: boolean | null) => listener?.({ isConnected }), unsubscribe }
}

describe("createAppendLogMobileLifecycle", () => {
  it("pulls when the app returns to the foreground (online, not loading)", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue([])
    const appState = mockAppState()
    createAppendLogMobileLifecycle(store, { appState: appState.module })
    appState.emit("active")
    expect(pullSpy).toHaveBeenCalledTimes(1)
  })

  it("does not pull on foreground while offline", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    store.getState().setOnline(false)
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue([])
    const appState = mockAppState()
    createAppendLogMobileLifecycle(store, { appState: appState.module })
    appState.emit("active")
    expect(pullSpy).not.toHaveBeenCalled()
  })

  it("does not pull on foreground when pullOnForeground is false", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    const pullSpy = vi.spyOn(store.getState(), "pull").mockResolvedValue([])
    const appState = mockAppState()
    createAppendLogMobileLifecycle(store, { appState: appState.module }, { pullOnForeground: false })
    appState.emit("active")
    expect(pullSpy).not.toHaveBeenCalled()
  })

  it("forwards NetInfo connectivity to setOnline and cleans up", () => {
    const store = createStarfishLog({ cursor: cursorWith(logClient()) })
    const appState = mockAppState()
    const netInfo = mockNetInfo()
    const cleanup = createAppendLogMobileLifecycle(store, { appState: appState.module, netInfo: netInfo.module })
    netInfo.emit(false)
    expect(store.getState().online).toBe(false)
    cleanup()
    expect(appState.removeFn).toHaveBeenCalled()
    expect(netInfo.unsubscribe).toHaveBeenCalled()
  })
})
