# Error Classification & Retry

Starfish's `SyncManager` retries on **conflict errors** (409) automatically. This page covers retry strategies for all other transient errors — rate limits, server failures, and network outages — at the HTTP layer.

> **Prerequisites:** [StarfishClient](02-starfish-client.md), [Offline & Connectivity](08-offline-connectivity.md)

## Error Classification

Every error from a sync operation falls into one of these categories:

| Category | Cause | Retryable | SDK handling |
|----------|-------|-----------|-------------|
| Network | `fetch` throws (`TypeError`, `AbortError`) | Yes | None — client throws |
| 401 Unauthorized | Expired or invalid auth token | Once (after refresh) | None — throws `StarfishHttpError` |
| 409 Conflict | Hash mismatch on push | Yes | `SyncManager` retries automatically |
| 429 Rate Limited | Too many requests | Yes (with backoff) | None — throws `StarfishHttpError` |
| 5xx Server Error | Server bug or overload | Yes (with backoff) | None — throws `StarfishHttpError` |
| Other 4xx | Bad request, forbidden, etc. | No | None — throws `StarfishHttpError` |

### Classifier function

```ts
import { StarfishHttpError } from "@drakkar.software/starfish-client"

type ErrorCategory = "network" | "auth" | "conflict" | "rate-limited" | "server" | "client" | "unknown"

function classifyError(err: unknown): ErrorCategory {
  if (err instanceof StarfishHttpError) {
    if (err.status === 401) return "auth"
    if (err.status === 409) return "conflict"
    if (err.status === 429) return "rate-limited"
    if (err.status >= 500) return "server"
    return "client"
  }
  if (err instanceof TypeError) return "network"
  return "unknown"
}
```

## Retry Fetch Wrapper

Inject retry logic via `StarfishClientOptions.fetch`. This wraps the native `fetch` with automatic retry for transient errors:

```ts
interface RetryOptions {
  /** Max retry attempts (default: 3) */
  maxRetries?: number
  /** Initial delay in ms (default: 500) */
  initialDelayMs?: number
  /** Max delay in ms (default: 10000) */
  maxDelayMs?: number
}

function createRetryFetch(options: RetryOptions = {}): typeof globalThis.fetch {
  const { maxRetries = 3, initialDelayMs = 500, maxDelayMs = 10_000 } = options

  return async (input, init) => {
    let attempt = 0

    while (true) {
      try {
        const response = await globalThis.fetch(input, init)

        if (response.status === 429 || response.status >= 500) {
          if (attempt >= maxRetries) return response

          const retryAfter = response.headers.get("Retry-After")
          const delay = retryAfter
            ? parseInt(retryAfter, 10) * 1000
            : Math.min(initialDelayMs * Math.pow(2, attempt), maxDelayMs)

          await new Promise((r) => setTimeout(r, delay + Math.random() * 100))
          attempt++
          continue
        }

        return response
      } catch (err) {
        // Network error (offline, DNS failure, etc.)
        if (attempt >= maxRetries) throw err

        await new Promise((r) =>
          setTimeout(r, Math.min(initialDelayMs * Math.pow(2, attempt), maxDelayMs))
        )
        attempt++
      }
    }
  }
}
```

Usage:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${token}` }),
  fetch: createRetryFetch({ maxRetries: 3 }),
})
```

This is **complementary** to `SyncManager`'s conflict retry. `SyncManager` handles 409 conflicts with its own backoff and merge logic. The retry fetch handles 429/5xx/network errors before they reach `SyncManager`.

## Circuit Breaker

After repeated failures, stop retrying to avoid wasting resources and battery. The circuit breaker has three states:

```
  ┌──────────┐   N failures   ┌──────┐   cooldown   ┌───────────┐
  │  CLOSED   │ ──────────────►│ OPEN  │ ────────────►│ HALF-OPEN  │
  │ (normal)  │                │(block)│              │ (test one) │
  └──────────┘                └──────┘              └───────────┘
       ▲                                                    │
       │              success                               │
       └────────────────────────────────────────────────────┘
                          failure → back to OPEN
```

```ts
class CircuitBreaker {
  private failures = 0
  private state: "closed" | "open" | "half-open" = "closed"
  private nextAttemptAt = 0

  constructor(
    private readonly threshold: number = 5,
    private readonly cooldownMs: number = 30_000,
  ) {}

  isOpen(): boolean {
    if (this.state === "open" && Date.now() >= this.nextAttemptAt) {
      this.state = "half-open"
    }
    return this.state === "open"
  }

  recordSuccess() {
    this.failures = 0
    this.state = "closed"
  }

  recordFailure() {
    this.failures++
    if (this.failures >= this.threshold) {
      this.state = "open"
      this.nextAttemptAt = Date.now() + this.cooldownMs
    }
  }
}
```

### Integrating with fetch

Wrap the retry fetch with circuit breaker protection:

```ts
function createResilientFetch(
  retryOptions?: RetryOptions,
  breakerOptions?: { threshold?: number; cooldownMs?: number },
): typeof globalThis.fetch {
  const retryFetch = createRetryFetch(retryOptions)
  const breaker = new CircuitBreaker(
    breakerOptions?.threshold,
    breakerOptions?.cooldownMs,
  )

  return async (input, init) => {
    if (breaker.isOpen()) {
      throw new Error("Circuit breaker is open — sync paused after repeated failures")
    }

    try {
      const response = await retryFetch(input, init)

      if (response.ok || response.status === 409) {
        breaker.recordSuccess()
      } else if (response.status >= 500) {
        breaker.recordFailure()
      }

      return response
    } catch (err) {
      breaker.recordFailure()
      throw err
    }
  }
}
```

## Auth Token Refresh on 401

When a sync request returns 401, refresh the token and retry once:

```ts
function createAuthRefreshFetch(
  refreshToken: () => Promise<void>,
): typeof globalThis.fetch {
  let isRefreshing = false

  return async (input, init) => {
    const response = await globalThis.fetch(input, init)

    if (response.status === 401 && !isRefreshing) {
      isRefreshing = true
      try {
        await refreshToken()
      } finally {
        isRefreshing = false
      }
      // Retry once — note: auth headers in `init` were already set by
      // StarfishClient before this wrapper was called. See caveat below.
      return globalThis.fetch(input, init)
    }

    return response
  }
}
```

The `isRefreshing` guard prevents multiple concurrent refresh calls when several requests fail at once.

**Important:** this wrapper retries the raw `fetch` call, but `StarfishClient` applies auth headers before calling `fetch`. To get new headers on the retry, the token refresh must update the state that `AuthProvider` reads (e.g., a variable or token store), and the retry must rebuild the request with fresh headers. A simpler approach is to handle 401 at the `AuthProvider` level:

```ts
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => {
    if (isTokenExpired()) {
      await refreshToken()
    }
    return { Authorization: `Bearer ${getToken()}` }
  },
})
```

This is often preferable because `AuthProvider` is called for every request and naturally integrates with the token lifecycle.

## Combining Strategies

Compose the layers into a single fetch pipeline:

```
Request → Auth refresh (401) → Circuit breaker → Retry (429/5xx/network) → globalThis.fetch
```

```ts
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => {
    if (isTokenExpired()) await refreshToken()
    return { Authorization: `Bearer ${getToken()}` }
  },
  fetch: createResilientFetch(
    { maxRetries: 3, initialDelayMs: 500 },
    { threshold: 5, cooldownMs: 30_000 },
  ),
})
```

## Integration with Sync Status

Extend the `deriveSyncStatus` function from [Offline & Connectivity](08-offline-connectivity.md) to surface error categories:

```ts
import type { StarfishState } from "@drakkar.software/starfish-client/zustand"

type SyncStatusValue = "synced" | "pending" | "syncing" | "error" | "offline"

function deriveSyncStatus(state: StarfishState): {
  status: SyncStatusValue
  message: string
} {
  if (!state.online) return { status: "offline", message: "No connection" }
  if (state.error) {
    // Classify the error message for better UX
    if (state.error.includes("429") || state.error.includes("rate"))
      return { status: "error", message: "Server busy — retrying soon" }
    if (state.error.includes("401") || state.error.includes("auth"))
      return { status: "error", message: "Session expired — please sign in" }
    if (state.error.includes("Circuit breaker"))
      return { status: "error", message: "Sync paused — will retry shortly" }
    return { status: "error", message: "Sync failed" }
  }
  if (state.syncing) return { status: "syncing", message: "Saving..." }
  if (state.dirty) return { status: "pending", message: "Unsaved changes" }
  return { status: "synced", message: "All changes saved" }
}
```

## Next Steps

- [StarfishClient](02-starfish-client.md) — custom fetch injection point
- [Offline & Connectivity](08-offline-connectivity.md) — sync status indicators
- [Logging & Observability](16-logging-observability.md) — logging errors and retries
