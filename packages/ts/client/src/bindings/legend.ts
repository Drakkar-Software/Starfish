import { observable } from "@legendapp/state"
import type { Observable } from "@legendapp/state"
import type { SyncManager } from "../sync.js"

export interface StarfishLegendState {
  data: Record<string, unknown>
  syncing: boolean
  online: boolean
  dirty: boolean
  error: string | null
}

export interface StarfishLegendStore {
  /** The observable state tree — read fields with `.get()` inside `observer` components. */
  state: Observable<StarfishLegendState>
  pull: () => Promise<void>
  set: (modifier: (current: Record<string, unknown>) => Record<string, unknown>) => void
  flush: () => Promise<void>
  setOnline: (online: boolean) => void
}

export interface CreateStarfishObservableOptions {
  /** Unique name for this collection (used for persistence keys when applicable). */
  name: string
  syncManager: SyncManager
  /** Pass `produce` from `immer` to enable draft-based mutations in `set()`. */
  produce?: <T>(base: T, recipe: (draft: T) => T | void) => T
}

export function createStarfishObservable(
  options: CreateStarfishObservableOptions,
): StarfishLegendStore {
  const state = observable<StarfishLegendState>({
    data: {},
    syncing: false,
    online: true,
    dirty: false,
    error: null,
  })

  const flush = async (): Promise<void> => {
    if (state.syncing.get() || !state.dirty.get()) return
    state.syncing.set(true)
    state.error.set(null)
    try {
      await options.syncManager.push(state.data.get())
      state.data.set(options.syncManager.getData())
      state.dirty.set(false)
    } catch (err) {
      state.error.set((err as Error).message)
    } finally {
      state.syncing.set(false)
    }
  }

  const pull = async (): Promise<void> => {
    state.syncing.set(true)
    state.error.set(null)
    try {
      await options.syncManager.pull()
      state.data.set(options.syncManager.getData())
    } catch (err) {
      state.error.set((err as Error).message)
    } finally {
      state.syncing.set(false)
    }
  }

  const set = (
    modifier: (current: Record<string, unknown>) => Record<string, unknown>,
  ): void => {
    try {
      const current = state.data.get()
      const next = options.produce
        ? options.produce(
            current,
            modifier as (draft: Record<string, unknown>) => Record<string, unknown> | void,
          )
        : modifier(current)
      state.data.set(next)
      state.dirty.set(true)
      state.error.set(null)
      if (state.online.get()) flush()
    } catch (err) {
      state.error.set((err as Error).message)
    }
  }

  const setOnline = (online: boolean): void => {
    state.online.set(online)
    if (online && state.dirty.get()) flush()
  }

  return { state, pull, set, flush, setOnline }
}
