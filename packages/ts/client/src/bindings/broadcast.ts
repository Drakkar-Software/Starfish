import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "./zustand.js"

interface BroadcastPayload {
  data: Record<string, unknown>
  dirty: boolean
}

/**
 * Syncs a Zustand Starfish store across browser tabs using BroadcastChannel.
 * Returns a cleanup function that closes the channel.
 */
export function setupBroadcastSync(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  const channel = new BroadcastChannel(`starfish-${name}`)
  let lastReceivedData: Record<string, unknown> | null = null

  channel.onmessage = (event: MessageEvent<BroadcastPayload>) => {
    lastReceivedData = event.data.data
    store.setState({ data: event.data.data, dirty: event.data.dirty })
  }

  const unsub = store.subscribe((state, prev) => {
    if (state.data === lastReceivedData) return
    if (state.data !== prev.data || state.dirty !== prev.dirty) {
      channel.postMessage({ data: state.data, dirty: state.dirty } satisfies BroadcastPayload)
    }
  })

  return () => {
    unsub()
    channel.close()
  }
}

/**
 * Syncs a Zustand Starfish store across browser tabs using storage events.
 * Fallback for environments without BroadcastChannel.
 * Returns a cleanup function.
 */
export function setupStorageFallback(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  const storageKey = `starfish-broadcast-${name}`
  let lastReceivedData: Record<string, unknown> | null = null

  const onStorage = (e: StorageEvent) => {
    if (e.key !== storageKey || !e.newValue) return
    const payload: BroadcastPayload = JSON.parse(e.newValue)
    lastReceivedData = payload.data
    store.setState({ data: payload.data, dirty: payload.dirty })
  }

  globalThis.addEventListener("storage", onStorage)

  const unsub = store.subscribe((state, prev) => {
    if (state.data === lastReceivedData) return
    if (state.data !== prev.data || state.dirty !== prev.dirty) {
      localStorage.setItem(
        storageKey,
        JSON.stringify({ data: state.data, dirty: state.dirty } satisfies BroadcastPayload),
      )
    }
  })

  return () => {
    unsub()
    globalThis.removeEventListener("storage", onStorage)
  }
}

/**
 * Auto-detects the best cross-tab sync mechanism and sets it up.
 * Uses BroadcastChannel when available, falls back to storage events.
 * Returns a cleanup function.
 */
export function setupCrossTabSync(
  store: StoreApi<StarfishStore>,
  name: string,
): () => void {
  if (typeof BroadcastChannel !== "undefined") {
    return setupBroadcastSync(store, name)
  }
  if (typeof globalThis.addEventListener === "function" && typeof localStorage !== "undefined") {
    return setupStorageFallback(store, name)
  }
  return () => {}
}
