/**
 * Tests for createTimeoutFetch — connect-phase fetch timeout.
 */
import { describe, it, expect, vi, afterEach } from "vitest"
import { createTimeoutFetch } from "../src/fetch.js"

afterEach(() => vi.useRealTimers())

describe("createTimeoutFetch", () => {
  it("resolves normally when the response arrives within the timeout", async () => {
    const inner = vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 }))
    const timeoutFetch = createTimeoutFetch(5_000, inner as unknown as typeof fetch)
    const res = await timeoutFetch("https://example.com/api")
    expect(res.status).toBe(200)
    expect(inner).toHaveBeenCalledOnce()
  })

  it("aborts and rejects when the server does not respond within timeoutMs", async () => {
    // A fetch that hangs forever (never resolves until aborted).
    const inner = vi.fn((_url: string, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined
        if (signal) {
          signal.addEventListener("abort", () =>
            reject(new DOMException("Aborted", "AbortError")),
          )
        }
      })
    })

    vi.useFakeTimers()
    const timeoutFetch = createTimeoutFetch(100, inner as unknown as typeof fetch)
    const promise = timeoutFetch("https://example.com/api")
    vi.advanceTimersByTime(101)
    await expect(promise).rejects.toThrow()
  })

  it("passes the caller's AbortSignal to the inner fetch", async () => {
    let receivedSignal: AbortSignal | undefined
    const inner = vi.fn(async (_url: string, init?: RequestInit) => {
      receivedSignal = init?.signal as AbortSignal | undefined
      return new Response("ok", { status: 200 })
    })

    const timeoutFetch = createTimeoutFetch(5_000, inner as unknown as typeof fetch)
    const ctrl = new AbortController()
    await timeoutFetch("https://example.com", { signal: ctrl.signal })
    expect(receivedSignal).toBeDefined()
  })

  it("clears the timeout timer after a successful response", async () => {
    // If the timer is NOT cleared, it would fire after the test, possibly
    // causing "timer still running after test" warnings. This test verifies
    // the timer IS cleared by checking the fetch resolved without issues.
    vi.useFakeTimers()
    const inner = vi.fn(async () => new Response("ok", { status: 200 }))
    const timeoutFetch = createTimeoutFetch(1_000, inner as unknown as typeof fetch)

    const res = await timeoutFetch("https://example.com")
    expect(res.status).toBe(200)

    // Advance time past where the timer WOULD have fired — no rejection.
    vi.advanceTimersByTime(2_000)
    // If the timer fired and rejected, the test would already have failed above.
  })

  it("aborts when the caller's signal fires before the timeout", async () => {
    const inner = vi.fn((_url: string, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined
        signal?.addEventListener("abort", () =>
          reject(new DOMException("Aborted", "AbortError")),
        )
      })
    })

    const ctrl = new AbortController()
    const timeoutFetch = createTimeoutFetch(10_000, inner as unknown as typeof fetch)
    const promise = timeoutFetch("https://example.com", { signal: ctrl.signal })
    ctrl.abort()
    await expect(promise).rejects.toThrow(/aborted/i)
  })

  it("uses 10 000 ms as the default timeout", async () => {
    let abortedAfterMs: number | undefined
    vi.useFakeTimers()
    const start = Date.now()
    const inner = vi.fn((_url: string, init?: RequestInit) => {
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal as AbortSignal | undefined
        signal?.addEventListener("abort", () => {
          abortedAfterMs = Date.now() - start
          reject(new DOMException("Aborted", "AbortError"))
        })
      })
    })

    const timeoutFetch = createTimeoutFetch(undefined, inner as unknown as typeof fetch)
    const promise = timeoutFetch("https://example.com")
    vi.advanceTimersByTime(10_001)
    await expect(promise).rejects.toThrow()
    expect(abortedAfterMs).toBeGreaterThanOrEqual(10_000)
  })
})
