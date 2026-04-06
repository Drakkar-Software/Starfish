// @vitest-environment jsdom
import { describe, it, expect } from "vitest"
import { renderHook, act } from "@testing-library/react"
import { createStore } from "zustand/vanilla"
import type { StarfishStore } from "../src/bindings/zustand.js"
import {
  useStarfish,
  useStarfishData,
  useSyncStatus,
  deriveSyncStatus,
} from "../src/bindings/react.js"

function createMockStore(initial?: Partial<StarfishStore>) {
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
