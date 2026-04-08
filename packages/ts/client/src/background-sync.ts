/**
 * Background Sync API integration for pending changes.
 * Uses the Web Background Sync API to retry failed sync operations
 * when connectivity is restored, even if the app is closed.
 */

export interface BackgroundSyncOptions {
  /** Sync event tag. Default: "starfish-sync" */
  tag?: string
}

/** Check if the Background Sync API is supported in the current environment. */
export function isBackgroundSyncSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    "SyncManager" in globalThis
  )
}

/**
 * Register a background sync event with the active service worker.
 * Returns true if registration succeeded, false if not supported or no active SW.
 */
export async function registerBackgroundSync(
  opts?: BackgroundSyncOptions,
): Promise<boolean> {
  if (!isBackgroundSyncSupported()) return false

  const tag = opts?.tag ?? "starfish-sync"

  try {
    const registration = await navigator.serviceWorker.ready
    // @ts-expect-error - SyncManager types may not be available
    await registration.sync.register(tag)
    return true
  } catch {
    return false
  }
}
