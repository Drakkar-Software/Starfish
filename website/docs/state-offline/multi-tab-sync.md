---
sidebar_position: 4
---

# Multi-Tab Sync

Keep multiple browser tabs in sync without redundant server pulls. When one tab pushes or pulls data, other tabs update instantly via the BroadcastChannel API.

> **Prerequisites:** [Zustand Binding](/state-offline/state-zustand), [Offline & Connectivity](/state-offline/offline-connectivity)

## The Problem

The Zustand binding persists `data` and `dirty` to `localStorage`, but persistence alone doesn't keep tabs in sync:

```
Tab A                          Tab B
  │                              │
  ├── pull() → new data          │ (in-memory store is stale)
  ├── localStorage updated       │
  │                              │ (won't read localStorage
  │                              │  until page reload)
  ▼                              ▼
```

Tab B's in-memory Zustand store won't see Tab A's changes until the user refreshes.

## BroadcastChannel

The [BroadcastChannel API](https://developer.mozilla.org/en-US/docs/Web/API/BroadcastChannel) lets same-origin tabs send messages to each other. Create one channel per store:

```ts
import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "@drakkar.software/starfish-client/zustand"

function setupBroadcastSync(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  const channel = new BroadcastChannel(`starfish-${name}`)
  let isReceiving = false

  // Broadcast local changes to other tabs
  const unsubscribe = store.subscribe(
    (state, prevState) => {
      if (!isReceiving && state.data !== prevState.data) {
        channel.postMessage({ type: "sync", data: state.data })
      }
    },
  )

  // Receive changes from other tabs
  channel.onmessage = (event) => {
    if (event.data?.type === "sync") {
      isReceiving = true
      store.setState({ data: event.data.data, dirty: false })
      isReceiving = false
    }
  }

  return () => {
    unsubscribe()
    channel.close()
  }
}
```

The `isReceiving` flag prevents echo loops — without it, receiving a message would trigger a state change that broadcasts back.

## Fallback: Storage Event

For environments without `BroadcastChannel`, the [`storage` event](https://developer.mozilla.org/en-US/docs/Web/API/Window/storage_event) fires in other tabs when `localStorage` changes. Since Zustand persistence already writes to `localStorage`, you get cross-tab notifications for free:

```ts
function setupStorageFallback(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  const storageKey = `starfish-${name}`

  const handleStorage = (event: StorageEvent) => {
    if (event.key !== storageKey || !event.newValue) return
    try {
      const { state } = JSON.parse(event.newValue)
      if (state?.data) {
        store.setState({ data: state.data, dirty: state.dirty ?? false })
      }
    } catch {
      // Ignore malformed storage entries
    }
  }

  window.addEventListener("storage", handleStorage)
  return () => window.removeEventListener("storage", handleStorage)
}
```

Limitation: the `storage` event only fires in **other** tabs (not the one that wrote), which is actually what we want. However, it's slower than `BroadcastChannel` and requires parsing the full persisted JSON.

## Combined Implementation

Detect support and pick the best available mechanism:

```ts
function setupCrossTabSync(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  if (typeof BroadcastChannel !== "undefined") {
    return setupBroadcastSync(store, name)
  }
  if (typeof window !== "undefined") {
    return setupStorageFallback(store, name)
  }
  // Server-side or non-browser — no-op
  return () => {}
}
```

Usage:

```ts
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"

const store = createStarfishStore({
  name: "settings",
  syncManager,
})

const cleanup = setupCrossTabSync(store, "settings")

// On app unmount
cleanup()
```

## Handling Pull from Another Tab

When Tab A pulls and gets new remote data, the state change broadcasts to Tab B automatically. Tab B receives the data and updates its store — **no redundant pull needed**.

```
Tab A                          Tab B
  │                              │
  ├── pull() → server            │
  ├── data updated in store      │
  ├── BroadcastChannel.post()  ──►── onmessage()
  │                              ├── store.setState({ data })
  │                              │   (no push, dirty stays false)
  ▼                              ▼
```

The receiving tab sets `dirty: false` because the data already came from the server — there's nothing to push.

## Multiple Stores

Set up cross-tab sync for each store independently:

```ts
const settingsStore = createStarfishStore({ name: "settings", syncManager: settingsSync })
const notesStore = createStarfishStore({ name: "notes", syncManager: notesSync })

const cleanups = [
  setupCrossTabSync(settingsStore, "settings"),
  setupCrossTabSync(notesStore, "notes"),
]

// Cleanup all on unmount
const cleanupAll = () => cleanups.forEach((fn) => fn())
```

Each store gets its own `BroadcastChannel`, so messages don't interfere across stores.

## React Hook

Wrap setup and cleanup in a React hook:

```ts
import { useEffect } from "react"

function useCrossTabSync(
  store: StoreApi<StarfishStore>,
  name: string,
) {
  useEffect(() => {
    return setupCrossTabSync(store, name)
  }, [store, name])
}

// Usage
function App() {
  useCrossTabSync(settingsStore, "settings")
  // ...
}
```

## When Not to Use

- **React Native / mobile**: there are no "tabs" — skip cross-tab sync entirely
- **Server-side rendering**: `BroadcastChannel` doesn't exist — the combined implementation handles this with the no-op fallback
- **Single-tab apps**: if your app opens in a single tab (e.g., Electron), cross-tab sync adds overhead with no benefit

## Next Steps

- [Zustand Binding](/state-offline/state-zustand) — persistence configuration
- [Offline & Connectivity](/state-offline/offline-connectivity) — sync status and connectivity
- [Integration Patterns](/integration-operations/integration-patterns) — restore-loop prevention (similar `isReceiving` guard)
