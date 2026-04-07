import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { startPolling, startAdaptivePolling } from "../src/polling.js"

describe("startPolling", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("calls pullFn at the specified interval", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })

    startPolling(pullFn, getState, 10_000)
    expect(pullFn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(10_000)
    expect(pullFn).toHaveBeenCalledTimes(1)

    vi.advanceTimersByTime(10_000)
    expect(pullFn).toHaveBeenCalledTimes(2)
  })

  it("skips pull when offline", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: false, syncing: false })

    startPolling(pullFn, getState, 5_000)
    vi.advanceTimersByTime(15_000)
    expect(pullFn).not.toHaveBeenCalled()
  })

  it("skips pull when syncing", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: true })

    startPolling(pullFn, getState, 5_000)
    vi.advanceTimersByTime(15_000)
    expect(pullFn).not.toHaveBeenCalled()
  })

  it("cleanup stops polling", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })

    const stop = startPolling(pullFn, getState, 5_000)
    vi.advanceTimersByTime(5_000)
    expect(pullFn).toHaveBeenCalledTimes(1)

    stop()
    vi.advanceTimersByTime(15_000)
    expect(pullFn).toHaveBeenCalledTimes(1)
  })

  it("defaults to 30s interval", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })

    startPolling(pullFn, getState)
    vi.advanceTimersByTime(29_999)
    expect(pullFn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(pullFn).toHaveBeenCalledTimes(1)
  })
})

describe("startAdaptivePolling", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it("uses navigator.connection.effectiveType for interval", () => {
    vi.stubGlobal("navigator", {
      connection: { effectiveType: "3g" },
    })

    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState)

    vi.advanceTimersByTime(29_999)
    expect(pullFn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1) // 30s for 3g
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.stop()
  })

  it("falls back to 15s when navigator.connection is unavailable", () => {
    vi.stubGlobal("navigator", {})

    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState)

    vi.advanceTimersByTime(14_999)
    expect(pullFn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1) // 15s fallback
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.stop()
  })

  it("pause and resume", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState, { intervalMs: 5_000 })

    vi.advanceTimersByTime(5_000)
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.pause()
    vi.advanceTimersByTime(15_000)
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.resume()
    vi.advanceTimersByTime(5_000)
    expect(pullFn).toHaveBeenCalledTimes(2)

    ctrl.stop()
  })

  it("stop clears interval permanently", () => {
    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState, { intervalMs: 5_000 })

    ctrl.stop()
    vi.advanceTimersByTime(30_000)
    expect(pullFn).not.toHaveBeenCalled()
  })

  it("respects custom intervals map", () => {
    vi.stubGlobal("navigator", {
      connection: { effectiveType: "slow" },
    })

    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState, {
      intervals: { slow: 7_000 },
    })

    vi.advanceTimersByTime(6_999)
    expect(pullFn).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.stop()
  })

  it("intervalMs option overrides network detection", () => {
    vi.stubGlobal("navigator", {
      connection: { effectiveType: "4g" }, // would be 10s
    })

    const pullFn = vi.fn().mockResolvedValue(undefined)
    const getState = () => ({ online: true, syncing: false })
    const ctrl = startAdaptivePolling(pullFn, getState, { intervalMs: 3_000 })

    vi.advanceTimersByTime(3_000)
    expect(pullFn).toHaveBeenCalledTimes(1)

    ctrl.stop()
  })
})
