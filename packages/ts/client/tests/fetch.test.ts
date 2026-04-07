import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  classifyError,
  createRetryFetch,
  CircuitBreaker,
  createResilientFetch,
} from "../src/fetch.js"

describe("classifyError", () => {
  it("classifies 401 as auth", () => {
    expect(classifyError({ status: 401 })).toBe("auth")
  })

  it("classifies 403 as auth", () => {
    expect(classifyError({ status: 403 })).toBe("auth")
  })

  it("classifies 409 as conflict", () => {
    expect(classifyError({ status: 409 })).toBe("conflict")
  })

  it("classifies 429 as rate-limited", () => {
    expect(classifyError({ status: 429 })).toBe("rate-limited")
  })

  it("classifies 500 as server", () => {
    expect(classifyError({ status: 500 })).toBe("server")
  })

  it("classifies 400 as client", () => {
    expect(classifyError({ status: 400 })).toBe("client")
  })

  it("classifies TypeError as network", () => {
    expect(classifyError(new TypeError("Failed to fetch"))).toBe("network")
  })

  it("classifies fetch failed errors as network", () => {
    expect(classifyError(new Error("fetch failed"))).toBe("network")
    expect(classifyError(new Error("Load failed"))).toBe("network")
    expect(classifyError(new Error("NetworkError when attempting to fetch"))).toBe("network")
  })

  it("classifies unknown errors", () => {
    expect(classifyError(new Error("something"))).toBe("unknown")
  })

  it("does not classify unrelated TypeError as network", () => {
    expect(classifyError(new TypeError("Cannot read properties of null"))).toBe("unknown")
  })

  it("classifies status 0 as network", () => {
    expect(classifyError({ status: 0 })).toBe("network")
  })
})

describe("createRetryFetch", () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => { vi.useRealTimers() })

  it("returns response on success without retrying", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 3 })
    const res = await retryFetch("https://example.com")

    expect(res.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })

  it("retries on 500 and succeeds", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response("err", { status: 500 }))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 3, initialDelayMs: 100 })
    const promise = retryFetch("https://example.com")

    // Advance past the retry delay
    await vi.advanceTimersByTimeAsync(200)

    const res = await promise
    expect(res.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(2)
    vi.unstubAllGlobals()
  })

  it("retries on 429 and respects Retry-After", async () => {
    const headers = new Headers({ "Retry-After": "1" })
    const mockFetch = vi.fn()
      .mockResolvedValueOnce(new Response("rate limited", { status: 429, headers }))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 3, initialDelayMs: 100 })
    const promise = retryFetch("https://example.com")

    await vi.advanceTimersByTimeAsync(1100)

    const res = await promise
    expect(res.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(2)
    vi.unstubAllGlobals()
  })

  it("does not retry on 400", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("bad", { status: 400 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 3 })
    const res = await retryFetch("https://example.com")

    expect(res.status).toBe(400)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    vi.unstubAllGlobals()
  })

  it("retries on network error", async () => {
    const mockFetch = vi.fn()
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValueOnce(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 3, initialDelayMs: 100 })
    const promise = retryFetch("https://example.com")

    await vi.advanceTimersByTimeAsync(200)

    const res = await promise
    expect(res.status).toBe(200)
    expect(mockFetch).toHaveBeenCalledTimes(2)
    vi.unstubAllGlobals()
  })

  it("gives up after maxRetries", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("err", { status: 500 }))
    vi.stubGlobal("fetch", mockFetch)

    const retryFetch = createRetryFetch({ maxRetries: 2, initialDelayMs: 50 })
    const promise = retryFetch("https://example.com")

    await vi.advanceTimersByTimeAsync(500)

    const res = await promise
    expect(res.status).toBe(500)
    expect(mockFetch).toHaveBeenCalledTimes(3) // 1 initial + 2 retries
    vi.unstubAllGlobals()
  })
})

describe("CircuitBreaker", () => {
  it("starts closed", () => {
    const breaker = new CircuitBreaker()
    expect(breaker.getState()).toBe("closed")
    expect(breaker.isOpen()).toBe(false)
  })

  it("opens after threshold failures", () => {
    const breaker = new CircuitBreaker({ threshold: 3 })
    breaker.recordFailure()
    breaker.recordFailure()
    expect(breaker.getState()).toBe("closed")
    breaker.recordFailure()
    expect(breaker.getState()).toBe("open")
    expect(breaker.isOpen()).toBe(true)
  })

  it("transitions to half-open after cooldown", () => {
    vi.useFakeTimers()
    const breaker = new CircuitBreaker({ threshold: 2, cooldownMs: 1000 })
    breaker.recordFailure()
    breaker.recordFailure()
    expect(breaker.getState()).toBe("open")

    vi.advanceTimersByTime(1000)
    expect(breaker.getState()).toBe("half-open")
    vi.useRealTimers()
  })

  it("resets to closed on success", () => {
    const breaker = new CircuitBreaker({ threshold: 2 })
    breaker.recordFailure()
    breaker.recordFailure()
    expect(breaker.getState()).toBe("open")

    breaker.recordSuccess()
    expect(breaker.getState()).toBe("closed")
    expect(breaker.isOpen()).toBe(false)
  })

  it("resets failure count on success before threshold", () => {
    const breaker = new CircuitBreaker({ threshold: 3 })
    breaker.recordFailure()
    breaker.recordFailure()
    breaker.recordSuccess()
    breaker.recordFailure()
    expect(breaker.getState()).toBe("closed")
  })

  it("re-opens immediately on failure during half-open", () => {
    vi.useFakeTimers()
    const breaker = new CircuitBreaker({ threshold: 2, cooldownMs: 1000 })
    breaker.recordFailure()
    breaker.recordFailure()
    expect(breaker.getState()).toBe("open")

    vi.advanceTimersByTime(1000)
    expect(breaker.getState()).toBe("half-open")

    breaker.recordFailure()
    expect(breaker.getState()).toBe("open")
    vi.useRealTimers()
  })
})

describe("createResilientFetch", () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => { vi.useRealTimers() })

  it("passes through successful requests", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const { fetch: resilientFetch, breaker } = createResilientFetch()
    const res = await resilientFetch("https://example.com")

    expect(res.status).toBe(200)
    expect(breaker.getState()).toBe("closed")
    vi.unstubAllGlobals()
  })

  it("throws when circuit is open", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }))
    vi.stubGlobal("fetch", mockFetch)

    const { fetch: resilientFetch, breaker } = createResilientFetch(
      { maxRetries: 0 },
      { threshold: 1 },
    )

    // Trip the breaker
    breaker.recordFailure()
    expect(breaker.isOpen()).toBe(true)

    await expect(resilientFetch("https://example.com")).rejects.toThrow(/too many consecutive failures/)
    vi.unstubAllGlobals()
  })

  it("trips breaker after enough 5xx responses", async () => {
    const mockFetch = vi.fn().mockResolvedValue(new Response("error", { status: 500 }))
    vi.stubGlobal("fetch", mockFetch)

    const { fetch: resilientFetch } = createResilientFetch(
      { maxRetries: 0 },
      { threshold: 2 },
    )

    // Two 500s should trip the breaker
    await resilientFetch("https://example.com")
    await resilientFetch("https://example.com")

    // Third call should be blocked by the breaker
    await expect(resilientFetch("https://example.com")).rejects.toThrow(/too many consecutive failures/)
    vi.unstubAllGlobals()
  })
})
