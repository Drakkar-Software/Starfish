---
sidebar_position: 2
---

# Legend State Binding

`createStarfishObservable` wraps a `SyncManager` in a [Legend State](https://legendapp.com/open-source/state/) observable with fine-grained reactivity.

> **Prerequisites:** [SyncManager](/client-core/sync-manager)

## Installation

```bash
npm install @drakkar.software/starfish-client @legendapp/state
npm install immer  # optional, for draft-based mutations
```

## Setup

```ts
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"
import { createStarfishObservable } from "@drakkar.software/starfish-client/legend"

const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

const settingsStore = createStarfishObservable({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: `/pull/users/${creds.userId}/settings`,
    pushPath: `/push/users/${creds.userId}/settings`,
  }),
})
```

### `CreateStarfishObservableOptions`

```ts
interface CreateStarfishObservableOptions {
  /** Unique name for this collection */
  name: string
  syncManager: SyncManager
  /** Pass `produce` from immer to enable draft-based mutations in set() */
  produce?: <T>(base: T, recipe: (draft: T) => T | void) => T
}
```

## Store Shape

```ts
interface StarfishLegendStore {
  /** Observable state tree — read fields with .get() inside observer components */
  state: Observable<StarfishLegendState>
  pull(): Promise<void>
  set(modifier: (current: Record<string, unknown>) => Record<string, unknown>): void
  flush(): Promise<void>
  setOnline(online: boolean): void
}

interface StarfishLegendState {
  data: Record<string, unknown>
  syncing: boolean
  online: boolean
  dirty: boolean
  error: string | null
}
```

## React Components

Wrap components with `observer()` to auto-subscribe to observables:

```tsx
import { observer, useSelector } from "@legendapp/state/react"

const Settings = observer(function Settings() {
  const { state, pull, set } = settingsStore

  useEffect(() => {
    pull()
  }, [])

  const data = state.data.get()
  const syncing = state.syncing.get()

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {(data.theme as string) ?? "default"}
    </button>
  )
})
```

### Fine-Grained Subscriptions

Components only re-render when the exact fields they read change:

```tsx
function ThemeBadge() {
  const theme = useSelector(() => settingsStore.state.data.get().theme as string)
  return <span>{theme}</span>
}
```

## Actions

The actions behave identically to the [Zustand binding](/state-offline/state-zustand):

| Action | Behavior |
|--------|----------|
| `set(modifier)` | Optimistic write, marks dirty, auto-flushes if online |
| `pull()` | Fetches remote data, updates `state.data` |
| `flush()` | Pushes dirty data. No-op if syncing or not dirty |
| `setOnline(online)` | Updates connectivity. Flushes on reconnect if dirty |

## Immer Support

```ts
import { produce } from "immer"

const notesStore = createStarfishObservable({
  name: "notes",
  syncManager,
  produce,
})

notesStore.set((draft) => {
  (draft.items as string[]).push("new note")
})
```

## Comparison with Zustand Binding

| Feature | Zustand | Legend State |
|---------|---------|-------------|
| Reactivity | Selector-based | Auto-tracking via `observer()` |
| Persistence | Built-in (localStorage, custom) | Not included |
| Redux DevTools | Built-in | Not included |
| Re-render granularity | Per-selector | Per-field (finer) |
| Bundle size | Requires `zustand` | Requires `@legendapp/state` |

Choose Zustand for persistence and devtools out of the box. Choose Legend State for finer-grained reactivity without manual selectors.

## Multiple Stores

```ts
const settingsStore = createStarfishObservable({
  name: "settings",
  syncManager: new SyncManager({ client, pullPath: "/pull/.../settings", pushPath: "/push/.../settings" }),
})

const notesStore = createStarfishObservable({
  name: "notes",
  syncManager: new SyncManager({ client, pullPath: "/pull/.../notes", pushPath: "/push/.../notes" }),
})
```

## Append-only logs

For **append-only collections**, use `createStarfishLogObservable` instead of `createStarfishObservable`. It's backed by an [`AppendLogCursor`](/server/append-only-collections#incremental-cursor-appendlogcursor) and is **read-only**: the observable holds `{ items, loading, online, error, checkpoint }` and exposes a `pull()` that fetches new elements and appends them (no `set`/`flush`/`dirty`).

```ts
import { AppendLogCursor } from "@drakkar.software/starfish-client"
import { createStarfishLogObservable } from "@drakkar.software/starfish-client/legend"
import { observer } from "@legendapp/state/react"

const cursor = new AppendLogCursor({ client, pullPath: "/pull/events", initialItems: await store.load() })
const log = createStarfishLogObservable({ cursor })
await log.pull()

const Feed = observer(function Feed() {
  return <>{log.state.items.get().map((e) => <Row key={e.ts} {...e} />)}</>
})
```

The cursor owns the items + checkpoint; persist by saving `cursor.getItems()` and rehydrate via `initialItems`.

## Next Steps

- [Zustand Binding](/state-offline/state-zustand) — alternative with persistence and devtools
- [Offline & Connectivity](/state-offline/offline-connectivity) — handling network changes
