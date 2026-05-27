import { observable } from "@legendapp/state"
import type { Observable } from "@legendapp/state"
import type { SyncManager } from "../sync.js"
import type { AppendLogCursor, AppendElement } from "../append-log.js"

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
      state.error.set(err instanceof Error ? err.message : String(err))
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
      state.error.set(err instanceof Error ? err.message : String(err))
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
      if (state.online.get()) flush().catch(() => {})
    } catch (err) {
      state.error.set(err instanceof Error ? err.message : String(err))
    }
  }

  const setOnline = (online: boolean): void => {
    state.online.set(online)
    if (online && state.dirty.get()) flush().catch(() => {})
  }

  return { state, pull, set, flush, setOnline }
}

// ── Append-only log binding ──────────────────────────────────────────
//
// The reactive counterpart for an append-only collection, backed by an
// `AppendLogCursor`. Read-only (a log only grows): no `set`/`flush`/`dirty`.
// The cursor owns the items + checkpoint; persist via `getItems()` and
// rehydrate by constructing the cursor with `initialItems`.
//
// The store assumes it is the SOLE driver of its cursor (it seeds from
// `cursor.getItems()` at construction and updates only via its own `pull()`);
// don't also call `cursor.pull()` directly, or the observable will go stale.

export interface StarfishLogObservableState {
  /** The full accumulated log, newest appended last. */
  items: AppendElement[]
  /** A `pull()` is in flight. */
  loading: boolean
  online: boolean
  error: string | null
  /** The cursor's checkpoint (max `ts` held). */
  checkpoint: number
}

export interface StarfishLogObservableStore {
  /** The observable state tree — read fields with `.get()` inside `observer` components. */
  state: Observable<StarfishLogObservableState>
  /** Pull elements newer than the checkpoint, append them, return the new batch.
   *  Errors are captured into `state.error`. */
  pull: () => Promise<AppendElement[]>
  setOnline: (online: boolean) => void
}

export interface CreateStarfishLogObservableOptions {
  cursor: AppendLogCursor
}

export function createStarfishLogObservable(
  options: CreateStarfishLogObservableOptions,
): StarfishLogObservableStore {
  const { cursor } = options
  const state = observable<StarfishLogObservableState>({
    // Seed from the cursor so a warm-started cursor's items show immediately.
    items: cursor.getItems(),
    loading: false,
    online: true,
    error: null,
    checkpoint: cursor.getCheckpoint(),
  })

  const pull = async (): Promise<AppendElement[]> => {
    if (state.loading.get()) return []
    state.loading.set(true)
    state.error.set(null)
    try {
      const batch = await cursor.pull()
      state.items.set(cursor.getItems())
      state.checkpoint.set(cursor.getCheckpoint())
      return batch
    } catch (err) {
      state.error.set(err instanceof Error ? err.message : String(err))
      return []
    } finally {
      state.loading.set(false)
    }
  }

  const setOnline = (online: boolean): void => {
    state.online.set(online)
  }

  return { state, pull, setOnline }
}
