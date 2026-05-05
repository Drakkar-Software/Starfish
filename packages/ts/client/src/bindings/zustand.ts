import { createStore, type StoreApi } from "zustand/vanilla"
import { useStore } from "zustand"
import {
  persist,
  subscribeWithSelector,
  createJSONStorage,
  type StateStorage,
} from "zustand/middleware"
import type { DevtoolsOptions } from "zustand/middleware"
import { useEffect, useRef, useState, useCallback } from "react"
import { StarfishClient } from "../client.js"
import { SyncManager } from "../sync.js"
import { setupCrossTabSync, type BroadcastableStore } from "../broadcast.js"
import type { AuthProvider, ConflictResolver } from "../types.js"
import type { SyncLogger } from "../logger.js"
import type { Validator } from "../validate.js"

export interface StarfishState {
  data: Record<string, unknown>
  syncing: boolean
  online: boolean
  dirty: boolean
  error: string | null
  /** Last-known server hash, persisted alongside `data`/`dirty`. Restored into the bound SyncManager on hydration. */
  hash: string | null
}

export interface StarfishActions {
  pull: () => Promise<void>
  set: (modifier: (current: Record<string, unknown>) => Record<string, unknown>) => void
  /** Update data without marking dirty or triggering flush. Use for restoring pulled data into the store. */
  restore: (data: Record<string, unknown>) => void
  flush: () => Promise<void>
  setOnline: (online: boolean) => void
}

export type StarfishStore = StarfishState & StarfishActions

export interface CreateStarfishStoreOptions {
  /** Unique name used as the persistence key (prefixed with `starfish-`) */
  name: string
  syncManager: SyncManager
  /** Pass `false` to disable persistence. Defaults to `localStorage` in browsers. */
  storage?: StateStorage | false
  /**
   * Wrap the store with Redux DevTools. Import `devtools` from `'zustand/middleware'`
   * and pass it directly — this keeps the import in your code, preventing
   * `import.meta.env` from being bundled in Metro/Hermes environments.
   *
   * @example
   * import { devtools } from 'zustand/middleware'
   * createStarfishStore({ devtools: (fn) => devtools(fn, { name: 'my-app' }) })
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  devtools?: (storeCreator: any) => any
  /** Pass `produce` from `immer` to enable draft-based mutations in `set()`. */
  produce?: <T>(base: T, recipe: (draft: T) => T | void) => T
  /**
   * Called when remote data arrives via `pull()` — **not** called for local `set()` writes.
   *
   * Use this to restore domain stores after a pull without worrying about feedback loops.
   * The callback fires **after** the Starfish store state is updated, so the store already
   * reflects the new data when this runs.
   *
   * Replaces the manual `isRestoring` flag pattern:
   * ```ts
   * createStarfishStore({
   *   name: "app",
   *   syncManager,
   *   onRemoteUpdate: (data) => {
   *     taskStore.setState({ tasks: data.tasks as Task[] })
   *     settingsStore.setState({ settings: data.settings as Settings })
   *   },
   * })
   * ```
   */
  onRemoteUpdate?: (data: Record<string, unknown>) => void
}

// Re-export DevtoolsOptions for convenience
export type { DevtoolsOptions }

export function createStarfishStore(
  options: CreateStarfishStoreOptions,
): StoreApi<StarfishStore> {
  const { name, syncManager, storage } = options

  type NamedSet = (partial: Partial<StarfishStore>, replace?: boolean, action?: string) => void

  const storeCreator = (
    rawSet: StoreApi<StarfishStore>["setState"],
    get: StoreApi<StarfishStore>["getState"],
  ): StarfishStore => {
    const set = rawSet as NamedSet
    return {
    data: {},
    syncing: false,
    online: true,
    dirty: false,
    error: null,
    hash: null,

    pull: async () => {
      set({ syncing: true, error: null }, false, "pull/start")
      try {
        await syncManager.pull()
        const newData = syncManager.getData()
        set({ data: newData, syncing: false, hash: syncManager.getHash() }, false, "pull/success")
        // Fire after state update so domain stores can read the updated Starfish state if needed.
        // Calling set() inside onRemoteUpdate does NOT re-enter pull(), so no feedback loop.
        options.onRemoteUpdate?.(newData)
      } catch (err) {
        set({ syncing: false, error: err instanceof Error ? err.message : String(err) }, false, "pull/error")
      }
    },

    set: (modifier) => {
      try {
        const next = options.produce
          ? options.produce(get().data, modifier as (draft: Record<string, unknown>) => Record<string, unknown> | void)
          : modifier(get().data)
        set({ data: next, dirty: true, error: null }, false, "set")
        if (get().online) get().flush().catch(() => {})
      } catch (err) {
        set({ error: err instanceof Error ? err.message : String(err) }, false, "set/error")
      }
    },

    restore: (data) => {
      set({ data }, false, "restore")
    },

    flush: async () => {
      if (get().syncing || !get().dirty) return
      set({ syncing: true, error: null }, false, "flush/start")
      try {
        await syncManager.push(get().data)
        set({ data: syncManager.getData(), syncing: false, dirty: false, hash: syncManager.getHash() }, false, "flush/success")
      } catch (err) {
        set({ syncing: false, error: err instanceof Error ? err.message : String(err) }, false, "flush/error")
      }
    },

    setOnline: (online) => {
      set({ online }, false, "setOnline")
      if (online && get().dirty) get().flush().catch(() => {})
    },
  }}

  const withPersist = storage === false
    ? storeCreator
    : persist(storeCreator, {
        name: `starfish-${name}`,
        storage: storage ? createJSONStorage(() => storage) : undefined,
        partialize: (state) => ({
          data: state.data,
          dirty: state.dirty,
          hash: state.hash,
        }),
        onRehydrateStorage: () => (state) => {
          // Only restore if the manager hasn't already received a hash from a live pull/push.
          // With async storage, pull() may resolve before hydration completes — the server's
          // hash always wins over the persisted one.
          if (state?.hash && syncManager.getHash() === null) syncManager.setHash(state.hash)
        },
      })

  const withSelector = subscribeWithSelector(withPersist)

  return createStore<StarfishStore>()(
    options.devtools ? options.devtools(withSelector) : withSelector,
  )
}

// ── React hooks ──────────────────────────────────────────────────────

/** Derived sync status for UI display. */
export type SyncStatus = "synced" | "syncing" | "pending" | "error" | "offline"

/** Derive a single sync status from store state. */
export function deriveSyncStatus(state: StarfishState): SyncStatus {
  if (!state.online) return "offline"
  if (state.error) return "error"
  if (state.syncing) return "syncing"
  if (state.dirty) return "pending"
  return "synced"
}

/**
 * Aggregate multiple sync statuses into a single worst-case status.
 * Priority (worst first): error > syncing > pending > offline > synced.
 */
export function aggregateSyncStatus(statuses: SyncStatus[]): SyncStatus {
  if (statuses.includes("error")) return "error"
  if (statuses.includes("syncing")) return "syncing"
  if (statuses.includes("pending")) return "pending"
  if (statuses.includes("offline")) return "offline"
  return "synced"
}

/** Use the full Starfish store state and actions. */
export function useStarfish(store: StoreApi<StarfishStore>): StarfishStore {
  return useStore(store)
}

/** Use only the synced data, with an optional selector for fine-grained subscriptions. */
export function useStarfishData<T = Record<string, unknown>>(
  store: StoreApi<StarfishStore>,
  selector?: (data: Record<string, unknown>) => T,
): T {
  return useStore(store, (state) =>
    selector ? selector(state.data) : (state.data as unknown as T),
  )
}

/** Use the derived sync status (synced | syncing | pending | error | offline). */
export function useSyncStatus(store: StoreApi<StarfishStore>): SyncStatus {
  return useStore(store, deriveSyncStatus)
}

/**
 * Subscribe to sync status changes outside of React.
 *
 * Framework-agnostic — works in React Native, Node.js, or anywhere hooks are unavailable.
 * The callback is invoked immediately with the current status and then on every change.
 *
 * ```ts
 * const unsub = subscribeSyncStatus(store, (status) => {
 *   updateStatusBar(status)
 * })
 *
 * // Later, to stop listening:
 * unsub()
 * ```
 */
export function subscribeSyncStatus(
  store: StoreApi<StarfishStore>,
  callback: (status: SyncStatus) => void,
): () => void {
  let prev = deriveSyncStatus(store.getState())
  callback(prev)
  return store.subscribe((state) => {
    const next = deriveSyncStatus(state)
    if (next !== prev) {
      prev = next
      callback(next)
    }
  })
}

/** Sets up cross-tab sync for a Starfish store. Cleans up on unmount. */
export function useCrossTabSync(
  store: StoreApi<StarfishStore>,
  name: string,
): void {
  useEffect(() => {
    return setupCrossTabSync(store as unknown as BroadcastableStore, name)
  }, [store, name])
}

/** Binds browser online/offline events to the store's setOnline action. Cleans up on unmount. */
export function useConnectivity(store: StoreApi<StarfishStore>): void {
  useEffect(() => {
    const handleOnline = () => store.getState().setOnline(true)
    const handleOffline = () => store.getState().setOnline(false)

    window.addEventListener("online", handleOnline)
    window.addEventListener("offline", handleOffline)

    return () => {
      window.removeEventListener("online", handleOnline)
      window.removeEventListener("offline", handleOffline)
    }
  }, [store])
}

/** Returns a human-readable "last synced" label that updates every 5 seconds. */
export function useLastSynced(store: StoreApi<StarfishStore>): string {
  const lastSyncedAt = useRef<number | null>(null)
  const [label, setLabel] = useState("Never synced")

  const computeLabel = useCallback(() => {
    if (lastSyncedAt.current === null) return "Never synced"
    const seconds = Math.floor((Date.now() - lastSyncedAt.current) / 1000)
    if (seconds < 10) return "Just now"
    if (seconds < 60) return `${seconds}s ago`
    return `${Math.floor(seconds / 60)}m ago`
  }, [])

  // Track sync completion
  useEffect(() => {
    let prevSyncing = store.getState().syncing
    const unsub = store.subscribe((state) => {
      if (prevSyncing && !state.syncing && !state.error) {
        lastSyncedAt.current = Date.now()
        setLabel(computeLabel())
      }
      prevSyncing = state.syncing
    })
    return unsub
  }, [store, computeLabel])

  // Update label periodically
  useEffect(() => {
    const timer = setInterval(() => {
      setLabel(computeLabel())
    }, 5000)
    return () => clearInterval(timer)
  }, [computeLabel])

  return label
}

// ── SyncInitializer hook ─────────────────────────────────────────────

export interface SyncInitConfig {
  serverUrl: string
  auth?: AuthProvider
  pullPath: string
  pushPath: string
  encryptionSecret?: string
  encryptionSalt?: string
  onConflict?: ConflictResolver
  /** Called when pulled data arrives. Use to restore domain stores. */
  onData?: (data: Record<string, unknown>) => void
  storeName?: string
  storage?: StateStorage | false
  fetch?: typeof globalThis.fetch
  logger?: SyncLogger
  validate?: Validator
}

/**
 * React hook that manages the full Starfish sync lifecycle.
 *
 * Creates StarfishClient → SyncManager → Zustand store, pulls on mount,
 * calls `onData` when remote data arrives, and tears down on unmount or
 * config change.
 *
 * Pass `null` to disable sync (returns `null`).
 */
export function useSyncInit(config: SyncInitConfig | null): StoreApi<StarfishStore> | null {
  const [store, setStore] = useState<StoreApi<StarfishStore> | null>(null)
  const onDataRef = useRef(config?.onData)
  onDataRef.current = config?.onData

  useEffect(() => {
    if (!config) {
      setStore(null)
      return
    }

    const client = new StarfishClient({
      baseUrl: config.serverUrl,
      auth: config.auth,
      fetch: config.fetch,
    })

    const syncManager = new SyncManager({
      client,
      pullPath: config.pullPath,
      pushPath: config.pushPath,
      encryptionSecret: config.encryptionSecret,
      encryptionSalt: config.encryptionSalt,
      onConflict: config.onConflict,
      logger: config.logger,
      validate: config.validate,
    })

    const newStore = createStarfishStore({
      name: config.storeName ?? "sync",
      syncManager,
      storage: config.storage,
      // onRemoteUpdate fires only for pull() results, never for local set() writes —
      // so no isRestoring flag is needed.
      onRemoteUpdate: (data) => {
        try {
          onDataRef.current?.(data)
        } catch (err) {
          newStore.setState({
            error: `onData failed: ${err instanceof Error ? err.message : String(err)}`,
          })
        }
      },
    })

    setStore(newStore)

    // Initial pull — errors are stored in state.error by the pull() action
    newStore.getState().pull().catch(() => {})

    return () => {
      setStore(null)
    }
    // Intentionally depend on serializable config values, not the object reference
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    config?.serverUrl,
    config?.pullPath,
    config?.pushPath,
    config?.encryptionSecret,
    config?.encryptionSalt,
    config?.storeName,
  ])

  return store
}
