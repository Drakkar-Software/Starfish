/**
 * Tests for the shared sync-store registry:
 *   acquireSyncStore / releaseSyncStore / clearSyncStoreRegistry / useSharedSyncStore
 *
 * Section 1 (pure-node): module-level registry logic — no React, no jsdom.
 * Section 2 (jsdom):     useSharedSyncStore React hook (// @vitest-environment jsdom
 *                        must be at the TOP of a file; here we use `@testing-library/react`
 *                        directly which works fine with the default jsdom environment that
 *                        vitest injects via the docblock in react.test.ts).
 */

// @vitest-environment jsdom

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

// ── Mocks ─────────────────────────────────────────────────────────────────────
// acquireSyncStore calls the real createStarfishStore (same module), which in turn
// calls syncManager.seedFromCache() and syncManager.pull(). We therefore mock the
// SyncManager constructor to return a lightweight stub with trackable methods.

const mockSeedFromCache = vi.fn()
const mockSyncManagerPull = vi.fn()
const mockGetData = vi.fn(() => ({}))
const mockGetHash = vi.fn(() => null)
const mockGetLastPullFromCache = vi.fn(() => false)
const mockResolve = vi.fn((_local: unknown, remote: unknown) => remote)
const mockPush = vi.fn()
const mockSetHash = vi.fn()

function makeSyncManagerStub() {
  return {
    seedFromCache: mockSeedFromCache,
    pull: mockSyncManagerPull,
    getData: mockGetData,
    getHash: mockGetHash,
    getLastPullFromCache: mockGetLastPullFromCache,
    resolve: mockResolve,
    push: mockPush,
    setHash: mockSetHash,
  }
}

const mockStarfishClientConstructor = vi.fn()
const mockSyncManagerConstructor = vi.fn()

vi.mock("../src/client.js", () => ({
  StarfishClient: vi.fn(function (this: unknown, opts: Record<string, unknown>) {
    mockStarfishClientConstructor(opts)
  }),
}))

vi.mock("../src/sync.js", () => ({
  SyncManager: vi.fn(function (this: unknown, opts: Record<string, unknown>) {
    mockSyncManagerConstructor(opts)
    // Copy stub methods onto this instance so createStarfishStore can call them.
    const stub = makeSyncManagerStub()
    Object.assign(this as object, stub)
  }),
}))

import {
  acquireSyncStore,
  releaseSyncStore,
  clearSyncStoreRegistry,
} from "../src/bindings/zustand.js"
import type { SharedSyncConfig } from "../src/bindings/zustand.js"

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Flush enough microtask ticks for seed().finally(pull()) to complete. */
async function flushPromises(): Promise<void> {
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
}

function makeConfig(storeName = "test-store"): SharedSyncConfig {
  return {
    serverUrl: "https://example.com",
    pullPath: "/pull/path",
    pushPath: "/push/path",
    storeName,
    // storage: false avoids localStorage access in tests
    storage: false,
  }
}

beforeEach(() => {
  mockSeedFromCache.mockReset()
  mockSyncManagerPull.mockReset()
  mockGetData.mockReset()
  mockGetData.mockReturnValue({})
  mockGetHash.mockReset()
  mockGetHash.mockReturnValue(null)
  mockGetLastPullFromCache.mockReset()
  mockGetLastPullFromCache.mockReturnValue(false)
  mockResolve.mockReset()
  mockResolve.mockImplementation((_l: unknown, r: unknown) => r)
  mockPush.mockReset()
  mockSetHash.mockReset()
  mockSeedFromCache.mockResolvedValue(false) // false = no cached data
  mockSyncManagerPull.mockResolvedValue(undefined)
  mockStarfishClientConstructor.mockReset()
  mockSyncManagerConstructor.mockReset()
  clearSyncStoreRegistry()
})

afterEach(() => {
  clearSyncStoreRegistry()
})

// ── First acquire ──────────────────────────────────────────────────────────────

describe("acquireSyncStore — first acquire", () => {
  it("constructs StarfishClient and SyncManager once", async () => {
    acquireSyncStore(makeConfig())
    await flushPromises()
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(1)
    expect(mockSyncManagerConstructor).toHaveBeenCalledTimes(1)
  })

  it("passes serverUrl to StarfishClient as baseUrl", async () => {
    acquireSyncStore(makeConfig())
    await flushPromises()
    const opts = mockStarfishClientConstructor.mock.calls[0][0] as Record<string, unknown>
    expect(opts.baseUrl).toBe("https://example.com")
  })

  it("forwards cacheFallbackStatuses to StarfishClient", async () => {
    acquireSyncStore({ ...makeConfig(), cacheFallbackStatuses: [429, 500, 503] })
    await flushPromises()
    const opts = mockStarfishClientConstructor.mock.calls[0][0] as Record<string, unknown>
    expect(opts.cacheFallbackStatuses).toEqual([429, 500, 503])
  })

  it("passes pullPath and pushPath to SyncManager", async () => {
    acquireSyncStore(makeConfig())
    await flushPromises()
    const opts = mockSyncManagerConstructor.mock.calls[0][0] as Record<string, unknown>
    expect(opts.pullPath).toBe("/pull/path")
    expect(opts.pushPath).toBe("/push/path")
  })

  it("calls seedFromCache then pull on first acquire", async () => {
    acquireSyncStore(makeConfig())
    await flushPromises()
    expect(mockSeedFromCache).toHaveBeenCalledTimes(1)
    expect(mockSyncManagerPull).toHaveBeenCalledTimes(1)
  })

  it("returns a store with a getState function", () => {
    const store = acquireSyncStore(makeConfig())
    expect(typeof store.getState).toBe("function")
  })
})

// ── Shared store on subsequent acquires ───────────────────────────────────────

describe("acquireSyncStore — shared store", () => {
  it("returns the same store for the same storeName", () => {
    const a = acquireSyncStore(makeConfig("shared"))
    const b = acquireSyncStore(makeConfig("shared"))
    expect(a).toBe(b)
  })

  it("does NOT call seedFromCache/pull on a second acquire", async () => {
    acquireSyncStore(makeConfig("shared"))
    await flushPromises()
    mockSeedFromCache.mockClear()
    mockSyncManagerPull.mockClear()
    acquireSyncStore(makeConfig("shared"))
    await flushPromises()
    expect(mockSeedFromCache).not.toHaveBeenCalled()
    expect(mockSyncManagerPull).not.toHaveBeenCalled()
  })

  it("creates separate client+manager for different storeNames", () => {
    acquireSyncStore(makeConfig("store-a"))
    acquireSyncStore(makeConfig("store-b"))
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(2)
  })
})

// ── RefCount and eviction ──────────────────────────────────────────────────────

describe("releaseSyncStore", () => {
  it("does nothing for an unknown storeName", () => {
    expect(() => releaseSyncStore("nonexistent")).not.toThrow()
  })

  it("entry survives while refCount > 0", async () => {
    acquireSyncStore(makeConfig("shared")) // refCount = 1
    acquireSyncStore(makeConfig("shared")) // refCount = 2
    releaseSyncStore("shared")             // refCount = 1
    await flushPromises()

    mockStarfishClientConstructor.mockClear()
    acquireSyncStore(makeConfig("shared")) // still alive: no new construction
    expect(mockStarfishClientConstructor).not.toHaveBeenCalled()
  })

  it("evicts the entry when refCount reaches 0", async () => {
    acquireSyncStore(makeConfig("evict"))
    await flushPromises()
    releaseSyncStore("evict") // refCount = 0 → evicted

    mockStarfishClientConstructor.mockClear()
    acquireSyncStore(makeConfig("evict")) // re-acquires fresh
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(1)
  })
})

// ── clearSyncStoreRegistry ─────────────────────────────────────────────────────

describe("clearSyncStoreRegistry", () => {
  it("empties the registry so the next acquire creates a fresh store", async () => {
    acquireSyncStore(makeConfig("a"))
    acquireSyncStore(makeConfig("b"))
    await flushPromises()
    clearSyncStoreRegistry()

    mockStarfishClientConstructor.mockClear()
    acquireSyncStore(makeConfig("a"))
    acquireSyncStore(makeConfig("b"))
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(2)
  })
})

// ── Account-switch mid-flight guard ───────────────────────────────────────────

describe("acquireSyncStore — account-switch guard", () => {
  it("does not fire pull if registry was cleared while seedFromCache was in flight", async () => {
    let resolveSeed!: (v: boolean) => void
    mockSeedFromCache.mockImplementation(
      () => new Promise<boolean>((r) => { resolveSeed = r }),
    )

    acquireSyncStore(makeConfig("switch-test"))
    // Registry cleared before seed completes (account switch)
    clearSyncStoreRegistry()
    // Now resolve seed — the identity guard should block pull
    resolveSeed(false)
    await flushPromises()

    expect(mockSyncManagerPull).not.toHaveBeenCalled()
  })
})

// ── Failed pull does not poison the entry ─────────────────────────────────────

describe("acquireSyncStore — pull failure resilience", () => {
  it("keeps the entry alive after a failed pull", async () => {
    mockSyncManagerPull.mockRejectedValueOnce(new Error("network error"))
    acquireSyncStore(makeConfig("failing"))
    await flushPromises()

    // Entry is still in registry: re-acquire does NOT construct a new client
    mockStarfishClientConstructor.mockClear()
    acquireSyncStore(makeConfig("failing"))
    expect(mockStarfishClientConstructor).not.toHaveBeenCalled()
  })
})

// ── React hook ────────────────────────────────────────────────────────────────

import { renderHook, act, waitFor } from "@testing-library/react"
import { useSharedSyncStore } from "../src/bindings/zustand.js"

describe("useSharedSyncStore — React hook", () => {
  it("returns null when config is null", () => {
    const { result } = renderHook(() => useSharedSyncStore(null))
    expect(result.current).toBeNull()
  })

  it("returns a store when config is provided", async () => {
    const { result } = renderHook(() => useSharedSyncStore(makeConfig("hook-basic")))
    await waitFor(() => expect(result.current).not.toBeNull())
    expect(typeof result.current!.getState).toBe("function")
  })

  it("two hooks with the same storeName share one store instance", async () => {
    const { result: r1 } = renderHook(() => useSharedSyncStore(makeConfig("hook-shared")))
    const { result: r2 } = renderHook(() => useSharedSyncStore(makeConfig("hook-shared")))

    await waitFor(() => expect(r1.current).not.toBeNull())
    await waitFor(() => expect(r2.current).not.toBeNull())

    expect(r1.current).toBe(r2.current)
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(1)
  })

  it("unmounting releases the store so the next acquire is fresh", async () => {
    const { result, unmount } = renderHook(() => useSharedSyncStore(makeConfig("hook-release")))
    await waitFor(() => expect(result.current).not.toBeNull())

    act(() => { unmount() })
    await flushPromises()

    // After unmount the entry is evicted; re-acquiring must construct a new client
    mockStarfishClientConstructor.mockClear()
    await act(async () => {
      acquireSyncStore(makeConfig("hook-release"))
      await flushPromises()
    })
    expect(mockStarfishClientConstructor).toHaveBeenCalledTimes(1)
  })
})
