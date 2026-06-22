/**
 * Parse a `Retry-After` header value into milliseconds.
 *
 * - Numeric string (`"30"`) — treated as seconds × 1000.
 * - HTTP-date string — delta from now in ms (floored to 0).
 * - `null`, empty, or unparseable — returns `opts.fallbackMs`.
 *
 * All results are clamped to `[0, opts.maxMs]`.
 */
export function parseRetryAfterMs(
  header: string | null | undefined,
  opts: { fallbackMs: number; maxMs: number },
): number {
  const { fallbackMs, maxMs } = opts
  const trimmed = header?.trim()
  if (trimmed) {
    const seconds = Number(trimmed)
    if (!isNaN(seconds)) return Math.min(seconds * 1000, maxMs)
    const date = Date.parse(trimmed)
    if (!isNaN(date)) return Math.min(Math.max(date - Date.now(), 0), maxMs)
  }
  return Math.min(fallbackMs, maxMs)
}

/** Error category returned by classifyError. */
export type ErrorCategory =
  | "network"
  | "auth"
  | "conflict"
  | "rate-limited"
  | "server"
  | "client"
  | "unknown"

/** Classify an error from a fetch response or network failure. */
export function classifyError(err: unknown): ErrorCategory {
  if (err instanceof Response || (err && typeof err === "object" && "status" in err)) {
    const status = (err as { status: unknown }).status
    if (typeof status !== "number" || isNaN(status)) return "unknown"
    if (status === 0) return "network"
    if (status === 401 || status === 403) return "auth"
    if (status === 409) return "conflict"
    if (status === 429) return "rate-limited"
    if (status >= 500) return "server"
    if (status >= 400) return "client"
  }
  if (err instanceof Error && /failed to fetch|fetch failed|network|load failed|ECONNREFUSED|ENOTFOUND/i.test(err.message)) return "network"
  return "unknown"
}

export interface RetryOptions {
  /** Max number of retries (default: 3). */
  maxRetries?: number
  /** Initial delay in ms before first retry (default: 500). */
  initialDelayMs?: number
  /** Maximum delay in ms (default: 10000). */
  maxDelayMs?: number
}

/**
 * Wraps a fetch function with automatic retry for retriable errors
 * (network failures, 429, 5xx). Respects Retry-After headers.
 */
export function createRetryFetch(options?: RetryOptions): typeof globalThis.fetch {
  const maxRetries = Math.max(0, options?.maxRetries ?? 3)
  const initialDelay = options?.initialDelayMs ?? 500
  const maxDelay = options?.maxDelayMs ?? 10_000

  return async (input, init?) => {
    let attempt = 0
    while (true) {
      try {
        const res = await globalThis.fetch(input, init)
        if (res.ok || attempt >= maxRetries) return res

        const category = classifyError(res)
        if (category !== "rate-limited" && category !== "server") return res

        const retryAfterHeader = res.headers.get("Retry-After")
        const exponentialDelay = Math.min(initialDelay * Math.pow(2, attempt), maxDelay)
        // When the header is present but unparseable, original falls back to
        // initialDelay (not exponential). Preserve that by checking presence first.
        const delay = parseRetryAfterMs(retryAfterHeader, {
          fallbackMs: retryAfterHeader?.trim() ? initialDelay : exponentialDelay,
          maxMs: maxDelay,
        })

        await new Promise<void>((r) => setTimeout(r, delay))
        attempt++
      } catch (err) {
        if (attempt >= maxRetries) throw err
        const category = classifyError(err)
        if (category !== "network") throw err

        const delay = Math.min(initialDelay * Math.pow(2, attempt), maxDelay)
        await new Promise<void>((r) => setTimeout(r, delay))
        attempt++
      }
    }
  }
}

type BreakerState = "closed" | "open" | "half-open"

export interface CircuitBreakerOptions {
  /** Number of consecutive failures to open the circuit (default: 5). */
  threshold?: number
  /** Cooldown in ms before transitioning from open to half-open (default: 30000). */
  cooldownMs?: number
}

/** Circuit breaker that prevents requests when the backend is unavailable. */
export class CircuitBreaker {
  private state: BreakerState = "closed"
  private failures = 0
  private openedAt = 0
  private readonly threshold: number
  private readonly cooldownMs: number

  constructor(options?: CircuitBreakerOptions) {
    this.threshold = options?.threshold ?? 5
    this.cooldownMs = options?.cooldownMs ?? 30_000
  }

  getState(): BreakerState {
    this.maybeTransition()
    return this.state
  }

  isOpen(): boolean {
    return this.getState() === "open"
  }

  recordSuccess(): void {
    this.failures = 0
    this.state = "closed"
  }

  recordFailure(): void {
    this.failures++
    if (this.state === "half-open" || this.failures >= this.threshold) {
      this.state = "open"
      this.openedAt = Date.now()
    }
  }

  private maybeTransition(): void {
    if (this.state === "open" && Date.now() - this.openedAt >= this.cooldownMs) {
      this.state = "half-open"
    }
  }
}

/**
 * Wraps fetch to gzip-compress string request bodies using the CompressionStream API.
 * Adds Content-Encoding: gzip header. Non-string bodies (ArrayBuffer, Blob, etc.)
 * are passed through uncompressed. Requires CompressionStream (browsers, Node.js 18+, Deno).
 */
export function createCompressedFetch(inner?: typeof globalThis.fetch): typeof globalThis.fetch {
  const baseFetch = inner ?? globalThis.fetch.bind(globalThis)
  return async (input, init?) => {
    if (!init?.body || typeof CompressionStream === "undefined") {
      return baseFetch(input, init)
    }

    const bodyText = typeof init.body === "string" ? init.body : null
    if (!bodyText) return baseFetch(input, init)

    try {
      const stream = new Blob([bodyText]).stream().pipeThrough(new CompressionStream("gzip"))
      const compressed = await new Response(stream).arrayBuffer()

      const normalized = Object.fromEntries(new Headers(init.headers as HeadersInit).entries())
      normalized["content-encoding"] = "gzip"

      return baseFetch(input, {
        ...init,
        body: compressed,
        headers: normalized,
      })
    } catch {
      return baseFetch(input, init)
    }
  }
}

/**
 * Wrap `fetch` to bound the **connect / Time-to-First-Byte** phase with a
 * timeout. The timer is cleared as soon as the response HEADERS arrive (i.e.
 * the `fetch()` promise resolves), so a slow large-body download after a fast
 * connection is not interrupted. Only the initial "will the server even
 * respond?" window is bounded.
 *
 * The wrapper composes with the caller's `AbortSignal`: if the caller's signal
 * fires first the request is still aborted and the timeout timer is cleaned up.
 *
 * @param timeoutMs     How long (in ms) to wait for the server to start
 *                      responding before aborting. Default `10 000`.
 * @param inner         Optional underlying `fetch` to wrap (defaults to
 *                      `globalThis.fetch`).
 *
 * @example
 * ```ts
 * import { createTimeoutFetch, createResilientFetch } from "@drakkar.software/starfish-client/fetch"
 *
 * const { fetch: resilient } = createResilientFetch()
 * const client = new StarfishClient({
 *   baseUrl: "https://api.example.com",
 *   fetch: createTimeoutFetch(8_000, resilient),
 * })
 * ```
 */
export function createTimeoutFetch(
  timeoutMs = 10_000,
  inner?: typeof globalThis.fetch,
): typeof globalThis.fetch {
  const baseFetch = inner ?? globalThis.fetch.bind(globalThis)
  return async (input, init?) => {
    const timeoutCtrl = new AbortController()
    const timer = setTimeout(() => timeoutCtrl.abort(new Error(`connect timeout after ${timeoutMs}ms`)), timeoutMs)

    // Compose with a caller-supplied AbortSignal if present.
    const callerSignal = init?.signal as AbortSignal | null | undefined
    let combinedSignal: AbortSignal

    if (callerSignal) {
      if (typeof AbortSignal.any === "function") {
        combinedSignal = AbortSignal.any([timeoutCtrl.signal, callerSignal])
      } else {
        // Polyfill for environments without AbortSignal.any.
        const combo = new AbortController()
        const onCallerAbort = () => combo.abort(callerSignal.reason)
        const onTimeout = () => combo.abort(timeoutCtrl.signal.reason)
        callerSignal.addEventListener("abort", onCallerAbort, { once: true })
        timeoutCtrl.signal.addEventListener("abort", onTimeout, { once: true })
        combinedSignal = combo.signal
      }
    } else {
      combinedSignal = timeoutCtrl.signal
    }

    try {
      const res = await baseFetch(input, { ...init, signal: combinedSignal })
      clearTimeout(timer) // Headers arrived — clear the connect timeout.
      return res
    } catch (err) {
      clearTimeout(timer)
      throw err
    }
  }
}

/**
 * Combines retry and circuit breaker into a single resilient fetch wrapper.
 * Rejects immediately when the circuit is open.
 */
export function createResilientFetch(
  retryOptions?: RetryOptions,
  breakerOptions?: CircuitBreakerOptions,
): { fetch: typeof globalThis.fetch; breaker: CircuitBreaker } {
  const breaker = new CircuitBreaker(breakerOptions)
  const retryFetch = createRetryFetch(retryOptions)

  const resilientFetch: typeof globalThis.fetch = async (input, init?) => {
    if (breaker.isOpen()) {
      const cooldown = Math.ceil((breakerOptions?.cooldownMs ?? 30_000) / 1000)
      throw new Error(`Request blocked: too many consecutive failures. Retry in ${cooldown}s.`)
    }

    try {
      const res = await retryFetch(input, init)
      if (res.status >= 500) {
        breaker.recordFailure()
      } else {
        breaker.recordSuccess()
      }
      return res
    } catch (err) {
      breaker.recordFailure()
      throw err
    }
  }

  return { fetch: resilientFetch, breaker }
}
