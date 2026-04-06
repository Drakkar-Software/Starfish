import { useStore } from "zustand"
import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore, StarfishState } from "./zustand.js"

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
