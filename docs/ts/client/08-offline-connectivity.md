# Offline & Connectivity

Both state bindings (Zustand and Legend State) implement an offline-first model: local writes are always instant, and pushes happen when connectivity is available.

> **Prerequisites:** [Zustand Binding](05-state-zustand.md) or [Legend State Binding](06-state-legend.md)

## Core Model

```
User writes data
       │
       ▼
  set(modifier)
  ├── Updates data locally (instant, optimistic)
  ├── Sets dirty = true
  └── If online → flush()
              │
              ▼
         flush()
         ├── If syncing or !dirty → no-op
         └── Push data to server
              ├── Success → dirty = false
              └── Failure → dirty remains true, error set
```

## State Flags

| Flag | Type | Description |
|------|------|-------------|
| `dirty` | `boolean` | Local changes exist that haven't been pushed |
| `online` | `boolean` | Whether the app believes it has network connectivity |
| `syncing` | `boolean` | A push or pull operation is in flight |
| `error` | `string \| null` | Last sync error message |

## Managing Connectivity

The `online` flag is **manually managed** — you set it based on your environment's network events.

### Browser

```ts
useEffect(() => {
  const handleOnline = () => store.getState().setOnline(true)
  const handleOffline = () => store.getState().setOnline(false)

  window.addEventListener("online", handleOnline)
  window.addEventListener("offline", handleOffline)

  return () => {
    window.removeEventListener("online", handleOnline)
    window.removeEventListener("offline", handleOffline)
  }
}, [])
```

### React Native

```ts
import NetInfo from "@react-native-community/netinfo"

useEffect(() => {
  const unsubscribe = NetInfo.addEventListener(({ isConnected }) => {
    store.getState().setOnline(!!isConnected)
  })
  return unsubscribe
}, [])
```

### Multiple Stores

If you have multiple stores, update them all together:

```ts
const stores = [settingsStore, notesStore]

const setAllOnline = (online: boolean) =>
  stores.forEach((s) => s.getState().setOnline(online))

window.addEventListener("online", () => setAllOnline(true))
window.addEventListener("offline", () => setAllOnline(false))
```

## Flush-on-Reconnect

When `setOnline(true)` is called and the store has `dirty: true`, it automatically triggers `flush()`. No manual intervention needed.

```ts
// User edits while offline → dirty = true
store.getState().set((d) => ({ ...d, theme: "dark" }))
// flush() is skipped because online = false

// Network returns
store.getState().setOnline(true)
// → automatically calls flush() because dirty = true
```

## Background Flush

In mobile apps, flush pending changes when the app goes to background:

```ts
import { AppState } from "react-native"

AppState.addEventListener("change", (state) => {
  if (state === "background") {
    const s = store.getState()
    if (s.dirty) s.flush()
  }
})
```

## Persistence Across Restarts

The Zustand binding persists `data` and `dirty` to storage (localStorage by default). On app restart:

- If `dirty: true` is restored from storage, you have un-pushed local changes
- Call `flush()` after initialization to push them, or call `pull()` first to reconcile

```ts
// After store creation, check for pending changes
const state = store.getState()
if (state.dirty) {
  await state.flush()
}
```

## Race Condition Safety

The `flush()` method guards against concurrent pushes:

```ts
// Simplified logic inside flush()
if (syncing || !dirty) return  // no-op
```

Multiple calls to `flush()` (e.g., from `set()` + `setOnline()` firing close together) are safe — only one push runs at a time.

## Error Recovery

Failed pushes set `error` but keep `dirty: true`. The data is not lost:

- On next `set()` call (if online): `flush()` retries
- On `setOnline(true)`: `flush()` retries
- Manual: call `flush()` directly

## Sync Status Indicators

Derive a single sync status from the store flags to give users clear feedback:

```ts
type SyncStatusValue = "synced" | "pending" | "syncing" | "error" | "offline"

function deriveSyncStatus(state: StarfishState): {
  status: SyncStatusValue
  message: string
} {
  if (!state.online) return { status: "offline", message: "No connection" }
  if (state.error) return { status: "error", message: state.error }
  if (state.syncing) return { status: "syncing", message: "Saving..." }
  if (state.dirty) return { status: "pending", message: "Unsaved changes" }
  return { status: "synced", message: "All changes saved" }
}
```

### React component

```tsx
function SyncStatusBadge() {
  // Custom equality prevents re-renders when the derived status hasn't changed
  const status = useStore(
    store,
    deriveSyncStatus,
    (a, b) => a.status === b.status && a.message === b.message,
  )
  const flush = useStore(store, (s) => s.flush)

  const colors: Record<SyncStatusValue, string> = {
    synced: "green",
    pending: "orange",
    syncing: "blue",
    error: "red",
    offline: "gray",
  }

  return (
    <span style={{ color: colors[status.status] }}>
      {status.message}
      {status.status === "error" && (
        <button onClick={flush}>Retry</button>
      )}
    </span>
  )
}
```

### Last sync timestamp

Track when the last successful sync happened for a "Last synced X minutes ago" display:

```ts
let lastSyncedAt: number | null = null

store.subscribe(
  (state) => state.syncing,
  (syncing, prevSyncing) => {
    // Push or pull just completed successfully
    if (prevSyncing && !syncing && !store.getState().error) {
      lastSyncedAt = Date.now()
    }
  },
)

function useLastSynced(): string {
  const [label, setLabel] = useState("")

  useEffect(() => {
    const interval = setInterval(() => {
      if (!lastSyncedAt) {
        setLabel("Never synced")
      } else {
        const seconds = Math.floor((Date.now() - lastSyncedAt) / 1000)
        if (seconds < 10) setLabel("Just now")
        else if (seconds < 60) setLabel(`${seconds}s ago`)
        else setLabel(`${Math.floor(seconds / 60)}m ago`)
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [])

  return label
}
```

### Multiple stores

When your app has multiple Starfish stores, aggregate their status:

```ts
// One useStore call per store — hooks must not be called in loops
function useGlobalSyncStatus(): SyncStatusValue {
  const s1 = useStore(settingsStore, (s) => deriveSyncStatus(s).status)
  const s2 = useStore(notesStore, (s) => deriveSyncStatus(s).status)
  const s3 = useStore(tasksStore, (s) => deriveSyncStatus(s).status)
  const statuses = [s1, s2, s3]

  // Worst status wins
  if (statuses.includes("error")) return "error"
  if (statuses.includes("syncing")) return "syncing"
  if (statuses.includes("pending")) return "pending"
  if (statuses.includes("offline")) return "offline"
  return "synced"
}
```

## Polling / Periodic Pull

The SDK doesn't auto-poll — pulls are explicit. For apps that need to stay in sync with changes from other devices, set up periodic polling.

### Basic polling

```ts
function startPolling(store: StoreApi<StarfishStore>, intervalMs = 30_000) {
  const timer = setInterval(() => {
    const { online, syncing } = store.getState()
    if (online && !syncing) {
      store.getState().pull()
    }
  }, intervalMs)

  return () => clearInterval(timer)
}

// Start on mount, stop on unmount
useEffect(() => {
  const stop = startPolling(settingsStore, 30_000)
  return stop
}, [])
```

### Adaptive polling

Adjust the interval based on network conditions and user activity:

```ts
function startAdaptivePolling(store: StoreApi<StarfishStore>) {
  let intervalMs = 10_000

  // Adapt to network quality (browser Network Information API)
  if ("connection" in navigator) {
    const conn = (navigator as any).connection
    const intervals: Record<string, number> = {
      "slow-2g": 120_000,
      "2g": 60_000,
      "3g": 30_000,
      "4g": 10_000,
    }
    intervalMs = intervals[conn?.effectiveType] ?? 15_000
  }

  let timer: ReturnType<typeof setInterval>
  let paused = false

  function schedule() {
    timer = setInterval(() => {
      if (paused) return
      const { online, syncing } = store.getState()
      if (online && !syncing) {
        store.getState().pull()
      }
    }, intervalMs)
  }

  schedule()

  return {
    /** Pause polling (e.g., when app is in background) */
    pause: () => { paused = true },
    /** Resume polling */
    resume: () => { paused = false },
    /** Stop polling permanently */
    stop: () => clearInterval(timer),
  }
}
```

### Pause in background

Avoid wasting battery when the app is not visible:

```ts
const polling = startAdaptivePolling(store)

// Browser
document.addEventListener("visibilitychange", () => {
  if (document.hidden) polling.pause()
  else polling.resume()
})

// React Native
AppState.addEventListener("change", (state) => {
  if (state === "active") polling.resume()
  else polling.pause()
})
```

### Pull-on-focus

An alternative to polling — pull only when the user returns to the app:

```ts
// Browser: pull when tab becomes visible
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    const { online, syncing } = store.getState()
    if (online && !syncing) store.getState().pull()
  }
})

// React Native: pull when app comes to foreground
AppState.addEventListener("change", (state) => {
  if (state === "active") {
    const { online, syncing } = store.getState()
    if (online && !syncing) store.getState().pull()
  }
})
```

This is less aggressive than polling but ensures the user always sees fresh data when they open the app.

## Next Steps

- [Integration Patterns](09-integration-patterns.md) — debounced push, restore-loop prevention, optimistic UI
- [Zustand Binding](05-state-zustand.md) — persistence configuration
- [Error Classification & Retry](15-error-retry.md) — retry strategies and error-aware sync status
