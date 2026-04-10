import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "./bindings/zustand.js"

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Minimal interface matching React Native's `AppState` module.
 * Pass `AppState` from `react-native` directly.
 */
export interface AppStateModule {
  addEventListener: (
    type: "change",
    listener: (state: string) => void,
  ) => { remove: () => void }
}

/**
 * Minimal interface matching `@react-native-community/netinfo`'s default export.
 * Pass `NetInfo` from `@react-native-community/netinfo` directly.
 */
export interface NetInfoModule {
  addEventListener: (
    listener: (state: { isConnected: boolean | null }) => void,
  ) => () => void
}

export interface MobileLifecycleDeps {
  /** React Native `AppState` module. */
  appState: AppStateModule
  /**
   * Optional: NetInfo module from `@react-native-community/netinfo`.
   * When provided, connectivity changes are forwarded to `store.getState().setOnline()`.
   */
  netInfo?: NetInfoModule
}

export interface MobileLifecycleOptions {
  /**
   * Pull remote changes when the app returns to the foreground.
   * Only pulls if the store is online and not already syncing.
   * Default: `true`.
   */
  pullOnForeground?: boolean
  /**
   * Flush dirty data when the app transitions to the background.
   * Only flushes if the store has unsaved changes.
   * Default: `true`.
   */
  flushOnBackground?: boolean
}

// ── Implementation ────────────────────────────────────────────────────────────

/**
 * Wires React Native app lifecycle events to a Starfish store.
 *
 * - **Background**: flushes pending changes before the OS suspends the app.
 * - **Foreground**: pulls remote changes when the user returns to the app.
 * - **NetInfo**: forwards connectivity changes to `store.getState().setOnline()`.
 *
 * Uses dependency injection so no `react-native` or `netinfo` imports are needed
 * in this package. Pass the modules directly:
 *
 * ```ts
 * import { AppState } from "react-native"
 * import NetInfo from "@react-native-community/netinfo"
 * import { createMobileLifecycle } from "@drakkar.software/starfish-client"
 *
 * // Call once, after the store is created:
 * const cleanup = createMobileLifecycle(
 *   store,
 *   { appState: AppState, netInfo: NetInfo },
 * )
 *
 * // In a React component (e.g. root layout):
 * useEffect(() => cleanup, [])
 * ```
 *
 * @returns A cleanup function that removes all event listeners.
 */
export function createMobileLifecycle(
  store: StoreApi<StarfishStore>,
  deps: MobileLifecycleDeps,
  options: MobileLifecycleOptions = {},
): () => void {
  const { pullOnForeground = true, flushOnBackground = true } = options

  const appSub = deps.appState.addEventListener("change", (appState) => {
    if (appState === "background" && flushOnBackground) {
      if (store.getState().dirty) {
        store.getState().flush().catch(() => {})
      }
    } else if (appState === "active" && pullOnForeground) {
      const { online, syncing } = store.getState()
      if (online && !syncing) {
        store.getState().pull().catch(() => {})
      }
    }
    // "inactive" (iOS transition) and other states are intentionally ignored
  })

  let netUnsub: (() => void) | null = null
  if (deps.netInfo) {
    netUnsub = deps.netInfo.addEventListener(({ isConnected }) => {
      store.getState().setOnline(!!isConnected)
    })
  }

  return () => {
    appSub.remove()
    netUnsub?.()
  }
}
