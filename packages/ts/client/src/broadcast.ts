/** Minimal store interface for cross-tab sync. Works with both Zustand and Legend bindings. */
export interface BroadcastableStore {
  getState(): { data: Record<string, unknown>; dirty: boolean }
  setState(partial: { data: Record<string, unknown>; dirty: boolean }): void
  subscribe(listener: (state: { data: Record<string, unknown>; dirty: boolean }, prev: { data: Record<string, unknown>; dirty: boolean }) => void): () => void
}

interface BroadcastPayload {
  data: Record<string, unknown>
  dirty: boolean
}

/**
 * Syncs a Starfish store across browser tabs using BroadcastChannel.
 * Works with any store that has getState/setState/subscribe (Zustand, Legend adapters, etc.).
 * Returns a cleanup function that closes the channel.
 */
export function setupBroadcastSync(
  store: BroadcastableStore,
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
 * Syncs a Starfish store across browser tabs using storage events.
 * Fallback for environments without BroadcastChannel.
 * Returns a cleanup function.
 */
export function setupStorageFallback(
  store: BroadcastableStore,
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
  store: BroadcastableStore,
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
