# Zustand Binding

`createStarfishStore` wraps a `SyncManager` in a [Zustand](https://github.com/pmndrs/zustand) store with persistence, optional devtools, and offline-first writes.

> **Prerequisites:** [SyncManager](03-sync-manager.md)

## Installation

```bash
npm install @drakkar.software/starfish-client zustand
npm install immer  # optional, for draft-based mutations
```

## Setup

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
})

// One store per collection — each syncs independently
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
  }),
})
```

### `CreateStarfishStoreOptions`

```ts
interface CreateStarfishStoreOptions {
  /** Unique name, used as persistence key (prefixed with `starfish-`) */
  name: string
  syncManager: SyncManager
  /** Pass `false` to disable persistence. Defaults to localStorage in browsers. */
  storage?: StateStorage | false
  /** Wrap the store with Redux DevTools. Import devtools from 'zustand/middleware' and pass it directly. */
  devtools?: (storeCreator: any) => any
  /** Pass `produce` from immer to enable draft-based mutations in set(). */
  produce?: <T>(base: T, recipe: (draft: T) => T | void) => T
}
```

## Store Shape

```ts
interface StarfishState {
  data: Record<string, unknown>  // the synced document
  syncing: boolean               // operation in flight?
  online: boolean                // network connectivity
  dirty: boolean                 // local changes pending push?
  error: string | null           // last sync error
}

interface StarfishActions {
  pull(): Promise<void>
  set(modifier: (current: Record<string, unknown>) => Record<string, unknown>): void
  flush(): Promise<void>
  setOnline(online: boolean): void
}

type StarfishStore = StarfishState & StarfishActions
```

## React Components

```tsx
import { useStore } from "zustand"

function Settings() {
  const { data, syncing, pull, set } = useStore(settingsStore)

  useEffect(() => {
    pull()
  }, [])

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {(data.theme as string) ?? "default"}
    </button>
  )
}
```

### Selectors

Subscribe to specific fields to avoid unnecessary re-renders:

```tsx
function ThemeBadge() {
  const theme = useStore(settingsStore, (s) => s.data.theme)
  return <span>{theme as string}</span>
}
```

The store includes `subscribeWithSelector` middleware, so you can also subscribe programmatically:

```ts
settingsStore.subscribe(
  (state) => state.data.theme,
  (theme) => console.log("theme changed:", theme),
)
```

## Actions

### `set(modifier)`

Applies an optimistic local write. If the store is online, automatically calls `flush()`.

```ts
settingsStore.getState().set((current) => ({
  ...current,
  theme: "dark",
}))
```

- Updates `data` immediately (optimistic)
- Sets `dirty: true`
- Calls `flush()` if `online` is `true`

### `pull()`

Fetches remote data and updates the store.

```ts
await settingsStore.getState().pull()
```

### `flush()`

Pushes dirty data to the server. No-op if already syncing or not dirty.

```ts
await settingsStore.getState().flush()
```

### `setOnline(online)`

Updates connectivity status. If going online with dirty data, triggers `flush()`.

```ts
settingsStore.getState().setOnline(true)
```

## Persistence

By default, `data` and `dirty` are persisted to `localStorage` under the key `starfish-{name}`.

```ts
// Default: localStorage
const store = createStarfishStore({ name: "settings", syncManager })
// Persists to localStorage key: "starfish-settings"

// Disable persistence
const store = createStarfishStore({ name: "settings", syncManager, storage: false })

// Custom storage (e.g., AsyncStorage for React Native)
import AsyncStorage from "@react-native-async-storage/async-storage"
const store = createStarfishStore({
  name: "settings",
  syncManager,
  storage: {
    getItem: (key) => AsyncStorage.getItem(key),
    setItem: (key, value) => AsyncStorage.setItem(key, value),
    removeItem: (key) => AsyncStorage.removeItem(key),
  },
})
```

Only `data` and `dirty` are persisted — `syncing`, `online`, and `error` are transient.

## Redux DevTools

Import `devtools` from `'zustand/middleware'` and pass it as a wrapper function. This keeps the import in your code so bundlers that don't support `import.meta.env` (Metro/Hermes, Expo web) are unaffected when devtools is unused.

```ts
import { devtools } from 'zustand/middleware'

const store = createStarfishStore({
  name: "settings",
  syncManager,
  devtools: (fn) => devtools(fn, { name: 'settings' }),
})
```

Action labels in DevTools:

| Action | When |
|--------|------|
| `pull/start` | Pull begins |
| `pull/success` | Pull completes |
| `pull/error` | Pull fails |
| `set` | Local data updated |
| `set/error` | Modifier threw |
| `flush/start` | Push begins |
| `flush/success` | Push completes |
| `flush/error` | Push fails |
| `setOnline` | Connectivity changed |

## Immer Support

Pass `produce` from Immer to enable draft-based mutations:

```ts
import { produce } from "immer"

const store = createStarfishStore({
  name: "notes",
  syncManager,
  produce,
})

// Mutate the draft directly — no spread needed
store.getState().set((draft) => {
  (draft.items as string[]).push("new note")
})
```

## Multiple Stores

Create one store per collection. Each syncs independently:

```ts
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({ client, pullPath: "/pull/.../settings", pushPath: "/push/.../settings" }),
})

const notesStore = createStarfishStore({
  name: "notes",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/.../notes",
    pushPath: "/push/.../notes",
    encryptionSecret: secret,
    encryptionSalt: salt,
  }),
})
```

## Next Steps

- [Legend State Binding](06-state-legend.md) — alternative with fine-grained reactivity
- [Offline & Connectivity](08-offline-connectivity.md) — handling network changes
