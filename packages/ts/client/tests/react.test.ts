// @vitest-environment jsdom
import { describe, it, expect, vi } from "vitest"
import { renderHook, act, waitFor } from "@testing-library/react"
import { createStore } from "zustand/vanilla"
import type { StarfishStore } from "../src/bindings/zustand.js"
import {
  useStarfish,
  useStarfishData,
  useSyncStatus,
  useSyncInit,
  deriveSyncStatus,
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
})
