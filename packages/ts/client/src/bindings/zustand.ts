import { createStore, type StoreApi } from "zustand/vanilla"
import { useStore } from "zustand"
import {
  persist,
  devtools,
  subscribeWithSelector,
  createJSONStorage,
  type StateStorage,
  type DevtoolsOptions,
} from "zustand/middleware"
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
  /** Enable Redux DevTools. Pass `true` or a `DevtoolsOptions` object. */
  devtools?: boolean | DevtoolsOptions
  /** Pass `produce` from `immer` to enable draft-based mutations in `set()`. */
  produce?: <T>(base: T, recipe: (draft: T) => T | void) => T
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

    pull: async () => {
      set({ syncing: true, error: null }, false, "pull/start")
      try {
        await syncManager.pull()
        set({ data: syncManager.getData(), syncing: false }, false, "pull/success")
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
        set({ data: syncManager.getData(), syncing: false, dirty: false }, false, "flush/success")
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
        }),
      })

  const withSelector = subscribeWithSelector(withPersist)

  if (options.devtools) {
    const devtoolsOpts: DevtoolsOptions =
      typeof options.devtools === "object"
        ? options.devtools
        : { name: `starfish-${name}` }
    return createStore<StarfishStore>()(devtools(withSelector, devtoolsOpts))
  }

  return createStore<StarfishStore>()(withSelector)
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
    })

    // Subscribe to data changes from pulls (not local sets)
    let lastDataRef = newStore.getState().data
    const unsub = newStore.subscribe((state) => {
      const data = state.data
      // Only call onData when data changes and store is not dirty
      // (dirty = false means data came from a pull, not a local set)
      if (data !== lastDataRef && !state.dirty) {
        try {
          onDataRef.current?.(data)
        } catch (err) {
          newStore.setState({
            error: `onData failed: ${err instanceof Error ? err.message : String(err)}`,
          })
        }
      }
      lastDataRef = data
    })

    setStore(newStore)

    // Initial pull — errors are stored in state.error by the pull() action
    newStore.getState().pull().catch(() => {})

    return () => {
      unsub()
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
