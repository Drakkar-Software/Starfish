// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { renderHook, act, waitFor } from "@testing-library/react"
import { createStore } from "zustand/vanilla"
import type { StarfishStore, StarfishLogStore } from "../src/bindings/zustand.js"
import {
  useStarfish,
  useStarfishData,
  useStarfishState,
  useSyncStatus,
  useSyncInit,
  deriveSyncStatus,
  aggregateSyncStatus,
  useCrossTabSync,
  useConnectivity,
  useLastSynced,
  useStarfishLog,
  useStarfishLogItems,
  useLogStatus,
} from "../src/bindings/zustand.js"

function createMockStore(initial?: Partial<StarfishStore>) {
  return createStore<StarfishStore>()((set) => ({
    data: {},
    syncing: false,
    online: true,
    dirty: false,
    error: null,
    pull: async () => {},
    set: () => {},
    restore: () => {},
    flush: async () => {},
    setOnline: () => {},
    ...initial,
  }))
}

describe("deriveSyncStatus", () => {
  it("returns offline when not online", () => {
    expect(deriveSyncStatus({ data: {}, syncing: false, online: false, dirty: false, error: null })).toBe("offline")
  })

  it("returns error when error is set", () => {
    expect(deriveSyncStatus({ data: {}, syncing: false, online: true, dirty: false, error: "fail" })).toBe("error")
  })

  it("returns syncing when syncing", () => {
    expect(deriveSyncStatus({ data: {}, syncing: true, online: true, dirty: false, error: null })).toBe("syncing")
  })

  it("returns pending when dirty", () => {
    expect(deriveSyncStatus({ data: {}, syncing: false, online: true, dirty: true, error: null })).toBe("pending")
  })

  it("returns synced when all clear", () => {
    expect(deriveSyncStatus({ data: {}, syncing: false, online: true, dirty: false, error: null })).toBe("synced")
  })

  it("offline takes priority over error", () => {
    expect(deriveSyncStatus({ data: {}, syncing: false, online: false, dirty: false, error: "fail" })).toBe("offline")
  })
})

describe("aggregateSyncStatus", () => {
  it("returns synced when all synced", () => {
    expect(aggregateSyncStatus(["synced", "synced"])).toBe("synced")
  })

  it("returns synced for empty array", () => {
    expect(aggregateSyncStatus([])).toBe("synced")
  })

  it("error takes priority over everything", () => {
    expect(aggregateSyncStatus(["synced", "syncing", "error", "pending"])).toBe("error")
  })

  it("syncing takes priority over pending", () => {
    expect(aggregateSyncStatus(["synced", "syncing", "pending"])).toBe("syncing")
  })

  it("pending takes priority over offline", () => {
    expect(aggregateSyncStatus(["synced", "pending", "offline"])).toBe("pending")
  })

  it("offline takes priority over synced", () => {
    expect(aggregateSyncStatus(["synced", "offline"])).toBe("offline")
  })
})

describe("useStarfish", () => {
  it("returns full store state", () => {
    const store = createMockStore({ data: { theme: "dark" } })
    const { result } = renderHook(() => useStarfish(store))

    expect(result.current.data).toEqual({ theme: "dark" })
    expect(result.current.online).toBe(true)
    expect(typeof result.current.pull).toBe("function")
  })

  it("re-renders on state change", () => {
    const store = createMockStore()
    const { result } = renderHook(() => useStarfish(store))

    act(() => {
      store.setState({ data: { updated: true } })
    })

    expect(result.current.data).toEqual({ updated: true })
  })
})

describe("useStarfishData", () => {
  it("returns data without selector", () => {
    const store = createMockStore({ data: { a: 1, b: 2 } })
    const { result } = renderHook(() => useStarfishData(store))

    expect(result.current).toEqual({ a: 1, b: 2 })
  })

  it("returns selected slice with selector", () => {
    const store = createMockStore({ data: { theme: "dark", lang: "en" } })
    const { result } = renderHook(() =>
      useStarfishData(store, (d) => d.theme as string),
    )

    expect(result.current).toBe("dark")
  })

  // Regression: a selector that derives a fresh array/object every call must not
  // make the snapshot referentially unstable (which loops under zustand v5 + React
  // 18/19 with "getSnapshot should be cached"). `shallow` equality returns the
  // cached reference while the data is unchanged.
  it("keeps a transform selector referentially stable across re-renders", () => {
    const store = createMockStore({ data: { items: [{ id: "a" }, { id: "b" }] } })
    let renderCount = 0
    const { result, rerender } = renderHook(() => {
      renderCount++
      // Fresh array on every call — the shape that used to loop.
      return useStarfishData(store, (d) =>
        (d.items as { id: string }[]).filter((x) => x.id !== "z"),
      )
    })

    const first = result.current
    expect(first).toEqual([{ id: "a" }, { id: "b" }])
    const countAfterMount = renderCount

    // Re-render the consumer without touching store data.
    rerender()

    // Same reference (shallow-cached) and no runaway render loop.
    expect(result.current).toBe(first)
    expect(renderCount).toBeLessThanOrEqual(countAfterMount + 1)
  })

  it("returns a new value only when the underlying data changes", () => {
    const store = createMockStore({ data: { items: [{ id: "a" }] } })
    const { result } = renderHook(() =>
      useStarfishData(store, (d) => (d.items as { id: string }[]).map((x) => x.id)),
    )

    const first = result.current
    expect(first).toEqual(["a"])

    act(() => {
      store.setState({ data: { items: [{ id: "a" }, { id: "b" }] } })
    })

    expect(result.current).toEqual(["a", "b"])
    expect(result.current).not.toBe(first)
  })
})

describe("useStarfishState", () => {
  it("returns the selected state slice", () => {
    const store = createMockStore({ error: "oops" })
    const { result } = renderHook(() => useStarfishState(store, (s) => s.error))
    expect(result.current).toBe("oops")
  })

  it("updates when the selected field changes", () => {
    const store = createMockStore({ online: true })
    const { result } = renderHook(() => useStarfishState(store, (s) => s.online))
    expect(result.current).toBe(true)
    act(() => { store.setState({ online: false }) })
    expect(result.current).toBe(false)
  })

  it("does not re-render when an unrelated field changes", () => {
    const store = createMockStore({ error: null })
    let renderCount = 0
    const { result } = renderHook(() => {
      renderCount++
      return useStarfishState(store, (s) => s.error)
    })
    const countAfterMount = renderCount
    act(() => { store.setState({ syncing: true }) })
    act(() => { store.setState({ dirty: true }) })
    // error didn't change — no extra renders beyond the initial
    expect(result.current).toBeNull()
    expect(renderCount).toBe(countAfterMount)
  })
})

describe("useSyncStatus", () => {
  it("returns synced for clean state", () => {
    const store = createMockStore()
    const { result } = renderHook(() => useSyncStatus(store))

    expect(result.current).toBe("synced")
  })

  it("updates when state changes", () => {
    const store = createMockStore()
    const { result } = renderHook(() => useSyncStatus(store))

    act(() => {
      store.setState({ dirty: true })
    })

    expect(result.current).toBe("pending")
  })
})

describe("useSyncInit", () => {
  it("returns null when config is null", () => {
    const { result } = renderHook(() => useSyncInit(null))
    expect(result.current).toBeNull()
  })

  it("creates a store and pulls on mount", async () => {
    const pullData = { key: "remote-value" }
    const mockFetch = vi.fn(async (url: string) => {
      if (typeof url === "string" && url.includes("/pull/")) {
        return new Response(JSON.stringify({
          data: pullData,
          hash: "h1",
          timestamp: 100,
        }), { status: 200, headers: { "Content-Type": "application/json" } })
      }
      return new Response("ok", { status: 200 })
    })

    const { result } = renderHook(() =>
      useSyncInit({
        serverUrl: "https://example.com",
        pullPath: "/pull/test",
        pushPath: "/push/test",
        storeName: "init-test",
        storage: false,
        fetch: mockFetch as unknown as typeof fetch,
      }),
    )

    // Store should be created
    await waitFor(() => {
      expect(result.current).not.toBeNull()
    })

    // Pull should have been called
    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled()
    })
  })

  it("forwards `namespace` so the store's client pulls the namespaced path", async () => {
    const mockFetch = vi.fn(async (url: string) =>
      url.includes("/pull/")
        ? new Response(JSON.stringify({ data: { ok: true }, hash: "h1", timestamp: 100 }), {
            status: 200, headers: { "Content-Type": "application/json" },
          })
        : new Response("ok", { status: 200 }),
    )

    renderHook(() =>
      useSyncInit({
        serverUrl: "https://example.com",
        namespace: "octobot",
        pullPath: "/pull/test",
        pushPath: "/push/test",
        storeName: "ns-test",
        storage: false,
        fetch: mockFetch as unknown as typeof fetch,
      }),
    )

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled()
    })
    const pullUrl = String(mockFetch.mock.calls.find((c) => String(c[0]).includes("/pull/"))?.[0])
    expect(pullUrl).toContain("/v1/octobot/pull/test")
  })

  it("omits the `/v1/<ns>` prefix when `namespace` is unset", async () => {
    const mockFetch = vi.fn(async (url: string) =>
      url.includes("/pull/")
        ? new Response(JSON.stringify({ data: {}, hash: "h1", timestamp: 100 }), {
            status: 200, headers: { "Content-Type": "application/json" },
          })
        : new Response("ok", { status: 200 }),
    )

    renderHook(() =>
      useSyncInit({
        serverUrl: "https://example.com",
        pullPath: "/pull/test",
        pushPath: "/push/test",
        storeName: "no-ns-test",
        storage: false,
        fetch: mockFetch as unknown as typeof fetch,
      }),
    )

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalled()
    })
    const pullUrl = String(mockFetch.mock.calls.find((c) => String(c[0]).includes("/pull/"))?.[0])
    expect(pullUrl).toContain("/pull/test")
    expect(pullUrl).not.toContain("/v1/")
  })

  it("tears down store on config change to null", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ data: {}, hash: "h", timestamp: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    )

    const { result, rerender } = renderHook(
      ({ config }: { config: Parameters<typeof useSyncInit>[0] }) => useSyncInit(config),
      {
        initialProps: {
          config: {
            serverUrl: "https://example.com",
            pullPath: "/pull/test",
            pushPath: "/push/test",
            storeName: "teardown-test",
            storage: false as const,
            fetch: mockFetch as unknown as typeof fetch,
          },
        },
      },
    )

    await waitFor(() => {
      expect(result.current).not.toBeNull()
    })

    rerender({ config: null })

    await waitFor(() => {
      expect(result.current).toBeNull()
    })
  })

  it("calls onData when pull delivers data", async () => {
    const onData = vi.fn()
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({
        data: { from: "server" },
        hash: "h1",
        timestamp: 100,
      }), { status: 200, headers: { "Content-Type": "application/json" } }),
    )

    renderHook(() =>
      useSyncInit({
        serverUrl: "https://example.com",
        pullPath: "/pull/test",
        pushPath: "/push/test",
        storeName: "ondata-test",
        storage: false,
        fetch: mockFetch as unknown as typeof fetch,
        onData,
      }),
    )

    await waitFor(() => {
      expect(onData).toHaveBeenCalledWith({ from: "server" })
    })
  })

  it("stores error when onData callback throws", async () => {
    const onData = vi.fn(() => { throw new Error("parse failed") })
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({
        data: { value: 1 },
        hash: "h1",
        timestamp: 100,
      }), { status: 200, headers: { "Content-Type": "application/json" } }),
    )

    const { result } = renderHook(() =>
      useSyncInit({
        serverUrl: "https://example.com",
        pullPath: "/pull/test",
        pushPath: "/push/test",
        storeName: "ondata-error-test",
        storage: false,
        fetch: mockFetch as unknown as typeof fetch,
        onData,
      }),
    )

    await waitFor(() => {
      expect(result.current).not.toBeNull()
    })

    await waitFor(() => {
      expect(result.current!.getState().error).toBe("onData failed: parse failed")
    })
  })
})

describe("useCrossTabSync", () => {
  it("sets up and tears down cross-tab sync", () => {
    const closeFn = vi.fn()
    const mockChannel = {
      onmessage: null as unknown,
      postMessage: vi.fn(),
      close: closeFn,
    }
    vi.stubGlobal("BroadcastChannel", vi.fn(() => mockChannel))

    const store = createMockStore()
    const { unmount } = renderHook(() => useCrossTabSync(store, "test-sync"))

    // BroadcastChannel should have been created
    expect(BroadcastChannel).toHaveBeenCalledWith("starfish-test-sync")

    unmount()
    expect(closeFn).toHaveBeenCalled()

    vi.unstubAllGlobals()
  })
})

describe("useConnectivity", () => {
  it("sets online true on online event", () => {
    const setOnline = vi.fn()
    const store = createMockStore({ setOnline })

    renderHook(() => useConnectivity(store))

    window.dispatchEvent(new Event("online"))
    expect(setOnline).toHaveBeenCalledWith(true)
  })

  it("sets online false on offline event", () => {
    const setOnline = vi.fn()
    const store = createMockStore({ setOnline })

    renderHook(() => useConnectivity(store))

    window.dispatchEvent(new Event("offline"))
    expect(setOnline).toHaveBeenCalledWith(false)
  })

  it("cleans up listeners on unmount", () => {
    const setOnline = vi.fn()
    const store = createMockStore({ setOnline })

    const { unmount } = renderHook(() => useConnectivity(store))
    unmount()

    window.dispatchEvent(new Event("online"))
    window.dispatchEvent(new Event("offline"))
    expect(setOnline).not.toHaveBeenCalled()
  })
})

describe("useLastSynced", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("returns 'Never synced' initially", () => {
    const store = createMockStore()
    const { result } = renderHook(() => useLastSynced(store))
    expect(result.current).toBe("Never synced")
  })

  it("returns 'Just now' after sync completes", () => {
    const store = createMockStore({ syncing: true })
    const { result } = renderHook(() => useLastSynced(store))

    act(() => {
      store.setState({ syncing: false })
    })

    expect(result.current).toBe("Just now")
  })

  it("does not update when sync completes with error", () => {
    const store = createMockStore({ syncing: true })
    const { result } = renderHook(() => useLastSynced(store))

    act(() => {
      store.setState({ syncing: false, error: "network error" })
    })

    expect(result.current).toBe("Never synced")
  })

  it("updates label over time", () => {
    const store = createMockStore({ syncing: true })
    const { result } = renderHook(() => useLastSynced(store))

    act(() => {
      store.setState({ syncing: false })
    })
    expect(result.current).toBe("Just now")

    act(() => {
      vi.advanceTimersByTime(15_000)
    })
    expect(result.current).toBe("15s ago")

    act(() => {
      vi.advanceTimersByTime(50_000) // total 65s
    })
    expect(result.current).toBe("1m ago")
  })
})

// ── Append-log hooks ─────────────────────────────────────────────────

function createMockLogStore(initial?: Partial<StarfishLogStore>) {
  return createStore<StarfishLogStore>()(() => ({
    items: [],
    loading: false,
    online: true,
    error: null,
    checkpoint: 0,
    pull: async () => [],
    setOnline: () => {},
    ...initial,
  }))
}

describe("useStarfishLog hooks", () => {
  it("useStarfishLog returns full state and actions", () => {
    const store = createMockLogStore({ checkpoint: 42 })
    const { result } = renderHook(() => useStarfishLog(store))
    expect(result.current.checkpoint).toBe(42)
    expect(typeof result.current.pull).toBe("function")
  })

  it("useStarfishLogItems returns items and re-renders on change", () => {
    const store = createMockLogStore({ items: [{ ts: 1, data: { a: 1 } }] })
    const { result } = renderHook(() => useStarfishLogItems(store))
    expect(result.current).toEqual([{ ts: 1, data: { a: 1 } }])

    act(() => {
      store.setState({ items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] })
    })
    expect(result.current).toHaveLength(2)
  })

  it("useStarfishLogItems supports a selector", () => {
    const store = createMockLogStore({ items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] })
    const { result } = renderHook(() => useStarfishLogItems(store, (items) => items.length))
    expect(result.current).toBe(2)
  })

  it("useStarfishLogItems keeps a transform selector referentially stable across re-renders", () => {
    const store = createMockLogStore({ items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] })
    const { result, rerender } = renderHook(() =>
      useStarfishLogItems(store, (items) => items.map((i) => i.ts)),
    )
    const first = result.current
    expect(first).toEqual([1, 2])
    rerender()
    expect(result.current).toBe(first)
  })

  it("useLogStatus derives status and updates on change", () => {
    const store = createMockLogStore()
    const { result } = renderHook(() => useLogStatus(store))
    expect(result.current).toBe("idle")

    act(() => { store.setState({ loading: true }) })
    expect(result.current).toBe("loading")

    act(() => { store.setState({ loading: false, online: false }) })
    expect(result.current).toBe("offline")
  })
})
