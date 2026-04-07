/**
 * Starfish + Zustand React example.
 *
 * Install:
 *   npm install @drakkar.software/starfish-client zustand
 *   npm install immer  # optional, for draft-based mutations
 */

import { useEffect } from "react"
import {
  StarfishClient,
  SyncManager,
  createUnionMerge,
  consoleSyncLogger,
} from "@drakkar.software/starfish-client"
import {
  createStarfishStore,
  useStarfish,
  useStarfishData,
  useSyncStatus,
  useSyncInit,
} from "@drakkar.software/starfish-client/zustand"
import { createRetryFetch } from "@drakkar.software/starfish-client/fetch"
import { setupCrossTabSync } from "@drakkar.software/starfish-client/broadcast"

// ---------------------------------------------------------------------------
// Example 1: Manual setup (one store per collection)
// ---------------------------------------------------------------------------

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
  fetch: createRetryFetch({ maxRetries: 3 }),
})

const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
    logger: consoleSyncLogger,
  }),
})

// Cross-tab sync (returns cleanup function)
const cleanupBroadcast = setupCrossTabSync(settingsStore, "settings")

export function Settings() {
  const { data, syncing, pull, set } = useStarfish(settingsStore)

  useEffect(() => {
    pull()
  }, [])

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {(data.theme as string) ?? "default"}
    </button>
  )
}

// Fine-grained: only re-renders when theme changes
export function ThemeBadge() {
  const theme = useStarfishData(settingsStore, (d) => d.theme as string)
  return <span>{theme}</span>
}

// Sync status indicator
export function SyncBadge() {
  const status = useSyncStatus(settingsStore)
  return <span>{status}</span>
}

// ---------------------------------------------------------------------------
// Example 2: useSyncInit — full lifecycle hook
// ---------------------------------------------------------------------------

export function SyncedApp({ userId }: { userId: string | null }) {
  // Pass null to disable sync — returns null
  const store = useSyncInit(
    userId
      ? {
          serverUrl: "https://api.example.com/v1",
          auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
          pullPath: `/pull/users/${userId}/data`,
          pushPath: `/push/users/${userId}/data`,
          storeName: "user-data",
          storage: false,
          onConflict: createUnionMerge(),
          logger: consoleSyncLogger,
          // Called when pulled data arrives — restore into domain stores
          onData: (data) => {
            console.log("Received data from server:", data)
          },
        }
      : null,
  )

  if (!store) return <p>Sync disabled</p>

  return <DataView store={store} />
}

function DataView({ store }: { store: NonNullable<ReturnType<typeof useSyncInit>> }) {
  const { data } = useStarfish(store)
  const status = useSyncStatus(store)

  return (
    <div>
      <p>Status: {status}</p>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Example 3: restore() — update store without triggering push
// ---------------------------------------------------------------------------

export function RestoreExample() {
  const { data, set, pull } = useStarfish(settingsStore)

  const handlePull = async () => {
    await pull()
    // After pull, use restore() to update domain stores without re-pushing
    const serverData = settingsStore.getState().data
    settingsStore.getState().restore(serverData)
  }

  return (
    <div>
      <button onClick={handlePull}>Pull & Restore</button>
      <button onClick={() => set((d) => ({ ...d, updated: true }))}>
        Local Edit (will push)
      </button>
      <pre>{JSON.stringify(data, null, 2)}</pre>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Connectivity listener (browser)
// ---------------------------------------------------------------------------

export function useConnectivity() {
  useEffect(() => {
    const setOnline = (online: boolean) =>
      settingsStore.getState().setOnline(online)

    window.addEventListener("online", () => setOnline(true))
    window.addEventListener("offline", () => setOnline(false))

    return () => {
      window.removeEventListener("online", () => setOnline(true))
      window.removeEventListener("offline", () => setOnline(false))
    }
  }, [])
}

// ---------------------------------------------------------------------------
// Placeholder — replace with your actual token retrieval
// ---------------------------------------------------------------------------

async function getToken(): Promise<string> {
  return "my-auth-token"
}
