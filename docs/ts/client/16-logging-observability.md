# Logging & Observability

Instrument Starfish sync operations for debugging, monitoring, and performance tracking. All patterns use existing SDK extension points — no source modifications needed.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Zustand Binding](05-state-zustand.md), [Integration Patterns](09-integration-patterns.md)

## Structured Logger Interface

Define a typed logger so sync events have a consistent shape:

```ts
interface SyncLogger {
  pullStart(store: string): void
  pullSuccess(store: string, durationMs: number): void
  pullError(store: string, error: string): void
  pushStart(store: string): void
  pushSuccess(store: string, durationMs: number): void
  pushError(store: string, error: string): void
  conflict(store: string, attempt: number): void
  retry(store: string, status: number, delayMs: number): void
}
```

### Console implementation

```ts
const consoleSyncLogger: SyncLogger = {
  pullStart: (store) => console.log(`[sync:${store}] pull started`),
  pullSuccess: (store, ms) => console.log(`[sync:${store}] pull OK (${ms}ms)`),
  pullError: (store, err) => console.error(`[sync:${store}] pull failed:`, err),
  pushStart: (store) => console.log(`[sync:${store}] push started`),
  pushSuccess: (store, ms) => console.log(`[sync:${store}] push OK (${ms}ms)`),
  pushError: (store, err) => console.error(`[sync:${store}] push failed:`, err),
  conflict: (store, attempt) => console.warn(`[sync:${store}] conflict (attempt ${attempt})`),
  retry: (store, status, delay) => console.log(`[sync:${store}] retry after ${status} in ${delay}ms`),
}
```

### No-op implementation

Use in production to eliminate logging overhead:

```ts
const noopSyncLogger: SyncLogger = {
  pullStart: () => {},
  pullSuccess: () => {},
  pullError: () => {},
  pushStart: () => {},
  pushSuccess: () => {},
  pushError: () => {},
  conflict: () => {},
  retry: () => {},
}
```

## Custom Fetch Logger

Inject logging via `StarfishClientOptions.fetch` to capture every HTTP request:

```ts
function createLoggingFetch(
  logger: SyncLogger,
  storeName: string,
): typeof globalThis.fetch {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url
    const method = init?.method ?? "GET"
    const start = performance.now()

    try {
      const response = await globalThis.fetch(input, init)
      const durationMs = Math.round(performance.now() - start)

      if (response.status === 409) {
        logger.conflict(storeName, 0)
      } else if (response.status === 429 || response.status >= 500) {
        logger.retry(storeName, response.status, 0)
      }

      return response
    } catch (err) {
      const durationMs = Math.round(performance.now() - start)
      logger.pushError(storeName, `${method} ${url} failed after ${durationMs}ms: ${err}`)
      throw err
    }
  }
}
```

### Composing with retry fetch

The logging fetch wraps the retry fetch from [Error Classification & Retry](15-error-retry.md), so you see every attempt:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${token}` }),
  // Logging wraps retry wraps native fetch
  fetch: createLoggingFetch(
    consoleSyncLogger,
    "settings",
  ),
})
```

If you're also using `createRetryFetch` or `createResilientFetch`, compose them:

```ts
const baseFetch = createResilientFetch({ maxRetries: 3 })

const loggingFetch: typeof globalThis.fetch = async (input, init) => {
  const start = performance.now()
  try {
    const response = await baseFetch(input, init)
    const ms = Math.round(performance.now() - start)
    consoleSyncLogger.pushSuccess("settings", ms)
    return response
  } catch (err) {
    consoleSyncLogger.pushError("settings", String(err))
    throw err
  }
}
```

## Sync Event Tracking

The Zustand binding uses `subscribeWithSelector`, so you can detect state transitions and map them to logger calls:

```ts
import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "@drakkar.software/starfish-client/zustand"

function attachSyncLogging(
  store: StoreApi<StarfishStore>,
  logger: SyncLogger,
  name: string,
) {
  let syncStartedAt = 0
  let lastOp: "push" | "pull" = "pull"

  store.subscribe(
    (state) => state.syncing,
    (syncing, prevSyncing) => {
      if (syncing && !prevSyncing) {
        // Sync started — check dirty to determine operation type
        syncStartedAt = performance.now()
        const isDirty = store.getState().dirty
        lastOp = isDirty ? "push" : "pull"
        if (isDirty) {
          logger.pushStart(name)
        } else {
          logger.pullStart(name)
        }
      }

      if (!syncing && prevSyncing) {
        // Sync ended
        const durationMs = Math.round(performance.now() - syncStartedAt)
        const { error, dirty } = store.getState()
        if (error) {
          lastOp === "push"
            ? logger.pushError(name, error)
            : logger.pullError(name, error)
        } else if (dirty) {
          logger.pushError(name, "Push completed but data still dirty")
        } else {
          lastOp === "push"
            ? logger.pushSuccess(name, durationMs)
            : logger.pullSuccess(name, durationMs)
        }
      }
    },
  )
}
```

Usage:

```ts
const store = createStarfishStore({ name: "settings", syncManager })
attachSyncLogging(store, consoleSyncLogger, "settings")
```

## Performance Metrics

Collect sync metrics over time for dashboards or analytics:

```ts
class SyncMetrics {
  private pullCount = 0
  private pushCount = 0
  private conflictCount = 0
  private errorCount = 0
  private totalPullMs = 0
  private totalPushMs = 0

  recordPull(durationMs: number) {
    this.pullCount++
    this.totalPullMs += durationMs
  }

  recordPush(durationMs: number) {
    this.pushCount++
    this.totalPushMs += durationMs
  }

  recordConflict() {
    this.conflictCount++
  }

  recordError() {
    this.errorCount++
  }

  getReport() {
    return {
      pulls: this.pullCount,
      pushes: this.pushCount,
      conflicts: this.conflictCount,
      errors: this.errorCount,
      avgPullMs: this.pullCount ? Math.round(this.totalPullMs / this.pullCount) : 0,
      avgPushMs: this.pushCount ? Math.round(this.totalPushMs / this.pushCount) : 0,
    }
  }

  reset() {
    this.pullCount = this.pushCount = this.conflictCount = this.errorCount = 0
    this.totalPullMs = this.totalPushMs = 0
  }
}
```

Wire it into a `SyncLogger`:

```ts
const metrics = new SyncMetrics()

const metricsLogger: SyncLogger = {
  pullStart: () => {},
  pullSuccess: (_, ms) => metrics.recordPull(ms),
  pullError: () => metrics.recordError(),
  pushStart: () => {},
  pushSuccess: (_, ms) => metrics.recordPush(ms),
  pushError: () => metrics.recordError(),
  conflict: () => metrics.recordConflict(),
  retry: () => {},
}

// Check metrics anytime
console.log(metrics.getReport())
// { pulls: 12, pushes: 8, conflicts: 1, errors: 0, avgPullMs: 145, avgPushMs: 210 }
```

## Sending Metrics to Analytics

Batch metrics and send them periodically:

```ts
function startMetricsReporter(
  metrics: SyncMetrics,
  send: (report: ReturnType<SyncMetrics["getReport"]>) => void,
  intervalMs = 60_000,
): () => void {
  const timer = setInterval(() => {
    const report = metrics.getReport()
    if (report.pulls > 0 || report.pushes > 0 || report.errors > 0) {
      send(report)
      metrics.reset()
    }
  }, intervalMs)

  return () => clearInterval(timer)
}

// Example: send to a generic analytics API
const stopReporting = startMetricsReporter(metrics, (report) => {
  analytics.track("starfish_sync_metrics", report)
})
```

**Privacy:** only log metadata (timing, counts, status codes). Never log decrypted document contents — the entire point of E2E encryption is that sync infrastructure never sees plaintext.

## Combining with Lifecycle Hooks

The [Sync Lifecycle Hooks](09-integration-patterns.md#sync-lifecycle-hooks) pattern wraps `pull` and `flush` actions on the store. Combine hooks with the logger for complete coverage:

```ts
function attachLoggedHooks(
  store: StoreApi<StarfishStore>,
  logger: SyncLogger,
  name: string,
) {
  const originalPull = store.getState().pull
  const originalFlush = store.getState().flush

  store.setState({
    pull: async () => {
      logger.pullStart(name)
      const start = performance.now()
      try {
        await originalPull()
        logger.pullSuccess(name, Math.round(performance.now() - start))
      } catch (err) {
        logger.pullError(name, (err as Error).message)
        throw err
      }
    },
    flush: async () => {
      logger.pushStart(name)
      const start = performance.now()
      try {
        await originalFlush()
        logger.pushSuccess(name, Math.round(performance.now() - start))
      } catch (err) {
        logger.pushError(name, (err as Error).message)
        throw err
      }
    },
  })
}
```

Call this **once, immediately after store creation** — the same caveat as [Sync Lifecycle Hooks](09-integration-patterns.md#sync-lifecycle-hooks).

## Next Steps

- [Integration Patterns](09-integration-patterns.md) — sync lifecycle hooks
- [Error Classification & Retry](15-error-retry.md) — error handling strategies
- [Offline & Connectivity](08-offline-connectivity.md) — sync status indicators
