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
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
} from "@drakkar.software/starfish-client"
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"

const creds = await bootstrapRootIdentity(passphrase)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: {
    getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
  },
})

// One store per collection — each syncs independently
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: `/pull/users/${creds.userId}/settings`,
    pushPath: `/push/users/${creds.userId}/settings`,
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
  /**
   * Auto re-attempt a failed flush with exponential backoff while the store
   * stays dirty + online. Omit to keep the default no-retry behavior.
   * Defaults when present: `maxRetries: 5`, `initialDelayMs: 500`, `maxDelayMs: 30_000`.
   */
  flushRetry?: { maxRetries?: number; initialDelayMs?: number; maxDelayMs?: number }
}
```

## Store Shape

```ts
interface StarfishState {
  data: Record<string, unknown>  // the synced document
  syncing: boolean               // operation in flight?
  online: boolean                // network connectivity
  dirty: boolean                 // local changes pending push?
  error: string | null           // last sync error (null when offline — see stale)
  hash: string | null            // last-known server hash; persisted for baseHash restore
  /**
   * True when the currently-shown `data` is a stale (not yet confirmed-live) snapshot:
   * either seeded from the client's offline cache via `seed()`, or kept from persisted
   * storage when a `pull()` failed because the transport was unreachable (offline /
   * DNS / timeout). A successful live pull clears it. Use it to drive an
   * "offline / showing last-synced data" indicator without surfacing an error.
   */
  stale: boolean
}

interface StarfishActions {
  pull(): Promise<void>
  set(modifier: (current: Record<string, unknown>) => Record<string, unknown>): void
  restore(data: Record<string, unknown>): void
  flush(): Promise<void>
  setOnline(online: boolean): void
  /**
   * Cache-first paint: populate `data` from the client's offline read-through cache
   * (if one is configured) without touching the network. A no-op without a cache or
   * on a cache miss. Call before the initial `pull()` to show last-synced data
   * immediately; the live pull then supersedes the seeded snapshot.
   */
  seed(): Promise<void>
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

**Offline behavior** — when the transport is unreachable (offline / DNS / timeout), `pull()` does
NOT set `error`. Instead it keeps the currently-shown `data` (which was already rehydrated from
persisted storage on cold start) and sets `stale: true` so the UI can show an "offline / showing
last-synced data" indicator without treating the situation as an error. HTTP errors (4xx / 5xx),
abort signals, and decrypt failures always set `error` as before.

This means **persist-backed stores are offline-first for reads** without needing a separate client
`cache`. On cold start, the persisted `starfish-{name}` entry rehydrates `data` immediately; the
first `pull()` then refreshes it from the server, or sets `stale: true` if the network is down.

### `flush()`

Pushes dirty data to the server. No-op if already syncing or not dirty.

```ts
await settingsStore.getState().flush()
```

**Self-healing retry** — pass `flushRetry` to `createStarfishStore` to enable automatic re-attempts on failure:

```ts
const store = createStarfishStore({
  name: "nodes",
  syncManager,
  flushRetry: { maxRetries: 5, initialDelayMs: 500, maxDelayMs: 30_000 },
})
```

After each failed flush, the store schedules the next attempt with jittered exponential backoff (`min(initialDelayMs × 2^attempt, maxDelayMs) + random(100ms)`). The counter resets on success, a fresh `set()` call, or when the store goes offline. `AbortError`s are never retried. Going offline via `setOnline(false)` cancels any pending retry timer immediately.

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

`data`, `dirty`, and `hash` are persisted — `syncing`, `online`, and `error` are transient. The persisted JSON shape is:

```json
{ "state": { "data": { "items": [] }, "dirty": false, "hash": "<server-hash>" }, "version": 0 }
```

On hydration, the stored `hash` is automatically restored into the bound `SyncManager` via `syncManager.setHash(hash)` before any pull or push runs. This means that after a page reload, wallet lock/unlock, or app restart, the first push sends `baseHash:<lastKnownHash>` instead of `null` — avoiding a spurious 409 conflict + recovery roundtrip.

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

// For an encrypted collection, build the encryptor from the keyring document.
// See 23-multi-recipient-delegated.md for keyring lifecycle.
const keyring = (await client.pull(`users/${creds.userId}/notes/_keyring`)).data as Keyring
const encryptor = await createKeyringEncryptor(keyring, {
  kemPubHex: creds.device.kemPub,
  kemPrivHex: creds.device.kemPriv,
})
const notesStore = createStarfishStore({
  name: "notes",
  syncManager: new SyncManager({
    client,
    pullPath: `/pull/users/${creds.userId}/notes`,
    pushPath: `/push/users/${creds.userId}/notes`,
    encryptor,
  }),
})
```

## Append-only logs

For **append-only collections** (a growing log rather than a read-merge-write document), use `createStarfishLog` instead of `createStarfishStore`. It's backed by an [`AppendLogCursor`](../server/append-only-collections.md#incremental-cursor-appendlogcursor) and is **read-only** — the store has `{ items, loading, online, error, checkpoint }` and a single `pull()` action that fetches new elements and appends them. There is no `set`/`flush`/`dirty`/conflict surface, and no `persist` middleware: the cursor owns the items + checkpoint (persist by saving `cursor.getItems()`, rehydrate via `initialItems`).

```ts
import { AppendLogCursor } from "@drakkar.software/starfish-client"
import {
  createStarfishLog,
  useStarfishLogItems,
  useLogStatus,
  useLogConnectivity,
} from "@drakkar.software/starfish-client/zustand"

const cursor = new AppendLogCursor({
  client,
  pullPath: "/pull/events",
  initialItems: await store.load(), // omit for a cold start
})
const logStore = createStarfishLog({ cursor })
await logStore.getState().pull() // fetch new, append; returns the new batch

function Feed() {
  const items = useStarfishLogItems(logStore)
  const status = useLogStatus(logStore) // "idle" | "loading" | "error" | "offline"
  useLogConnectivity(logStore)
  return <>{items.map((e) => <Row key={e.ts} {...e} />)}</>
}
```

Hooks: `useStarfishLog`, `useStarfishLogItems(store, selector?)`, `useLogStatus`, `subscribeLogStatus` (framework-agnostic), `useLogConnectivity`. For React Native, [`createAppendLogMobileLifecycle`](08-offline-connectivity.md) pulls on foreground. Polling works as-is: `startPolling(() => logStore.getState().pull(), () => logStore.getState())`.

## Next Steps

- [Legend State Binding](06-state-legend.md) — alternative with fine-grained reactivity
- [Offline & Connectivity](08-offline-connectivity.md) — handling network changes
