/**
 * Tests for the CAS retry helper.
 */
import { describe, it, expect, vi, afterEach } from "vitest"
import { ConflictError } from "@drakkar.software/starfish-client"
import { runCas } from "../src/cas-retry.js"

afterEach(() => vi.useRealTimers())

describe("runCas", () => {
  it("returns the result of the first successful call", async () => {
    vi.useFakeTimers()
    const fn = vi.fn().mockResolvedValue("ok")
    const p = runCas(fn)
    await vi.runAllTimersAsync()
    expect(await p).toBe("ok")
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it("passes attempt=0 on the first call", async () => {
    vi.useFakeTimers()
    const fn = vi.fn().mockResolvedValue("ok")
    const p = runCas(fn)
    await vi.runAllTimersAsync()
    await p
    expect(fn.mock.calls[0][0]).toMatchObject({ attempt: 0, currentHash: "" })
  })

  it("retries on ConflictError and increments attempt", async () => {
    vi.useFakeTimers()
    const conflict = new ConflictError("conflict", 409)
    const fn = vi.fn()
      .mockRejectedValueOnce(conflict)
      .mockRejectedValueOnce(conflict)
      .mockResolvedValue("success")
    const p = runCas(fn)
    await vi.runAllTimersAsync()
    expect(await p).toBe("success")
    expect(fn).toHaveBeenCalledTimes(3)
    expect(fn.mock.calls[0][0]).toMatchObject({ attempt: 0 })
    expect(fn.mock.calls[1][0]).toMatchObject({ attempt: 1 })
    expect(fn.mock.calls[2][0]).toMatchObject({ attempt: 2 })
  })

  it("schedules backoff between attempts", async () => {
    vi.useFakeTimers()
    const conflict = new ConflictError("conflict", 409)
    let call = 0
    const fn = vi.fn(async () => {
      call++
      if (call < 3) throw conflict
      return "ok"
    })
    const p = runCas(fn)
    // First attempt runs immediately; backoffs are scheduled as timers.
    await vi.runAllTimersAsync()
    expect(await p).toBe("ok")
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it("throws after MAX_ATTEMPTS (5) ConflictErrors — does not retry a 6th time", async () => {
    vi.useFakeTimers()
    const conflict = new ConflictError("conflict", 409)
    const fn = vi.fn().mockRejectedValue(conflict)
    // Attach assertion BEFORE advancing timers to avoid unhandled-rejection warning.
    const assertion = expect(runCas(fn)).rejects.toThrow(ConflictError)
    await vi.runAllTimersAsync()
    await assertion
    expect(fn).toHaveBeenCalledTimes(5)
  })

  it("propagates non-conflict errors immediately without retry", async () => {
    vi.useFakeTimers()
    const boom = new Error("network error")
    const fn = vi.fn().mockRejectedValue(boom)
    const assertion = expect(runCas(fn)).rejects.toThrow("network error")
    await vi.runAllTimersAsync()
    await assertion
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it("passes currentHash from 409 response to the next attempt", async () => {
    vi.useFakeTimers()
    const conflict = new ConflictError("H_conflict")
    const fn = vi.fn()
      .mockRejectedValueOnce(conflict)
      .mockResolvedValue("ok")
    const p = runCas(fn)
    await vi.runAllTimersAsync()
    await p
    // Second call should receive the currentHash from the ConflictError.
    expect(fn.mock.calls[1][0]).toMatchObject({ currentHash: "H_conflict" })
  })
})
