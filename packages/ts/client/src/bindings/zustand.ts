import { createStore, type StoreApi } from "zustand/vanilla"
import {
  persist,
  devtools,
  subscribeWithSelector,
  createJSONStorage,
  type StateStorage,
  type DevtoolsOptions,
} from "zustand/middleware"
import type { SyncManager } from "../sync.js"

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
        set({ syncing: false, error: (err as Error).message }, false, "pull/error")
      }
    },

    set: (modifier) => {
      try {
        const next = options.produce
          ? options.produce(get().data, modifier as (draft: Record<string, unknown>) => Record<string, unknown> | void)
          : modifier(get().data)
        set({ data: next, dirty: true, error: null }, false, "set")
        if (get().online) get().flush()
      } catch (err) {
        set({ error: (err as Error).message }, false, "set/error")
      }
    },

    flush: async () => {
      if (get().syncing || !get().dirty) return
      set({ syncing: true, error: null }, false, "flush/start")
      try {
        await syncManager.push(get().data)
        set({ data: syncManager.getData(), syncing: false, dirty: false }, false, "flush/success")
      } catch (err) {
        set({ syncing: false, error: (err as Error).message }, false, "flush/error")
      }
    },

    setOnline: (online) => {
      set({ online }, false, "setOnline")
      if (online && get().dirty) get().flush()
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
