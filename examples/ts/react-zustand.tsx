/**
 * Starfish v3.0 + Zustand + React.
 *
 * Demonstrates wiring a v3 cap-cert provider into Zustand-backed sync.
 *
 * Install:
 *   npm install @drakkar.software/starfish-client zustand react
 */

import { useEffect, useMemo } from "react"
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
  createUnionMerge,
  consoleSyncLogger,
  type StarfishCapProvider,
  type DeviceCredentials,
} from "@drakkar.software/starfish-client"
import {
  createStarfishStore,
  useStarfish,
  useStarfishData,
  useSyncStatus,
  useSyncInit,
} from "@drakkar.software/starfish-client/zustand"
import { setupCrossTabSync } from "@drakkar.software/starfish-client/broadcast"

// ---------------------------------------------------------------------------
// Cap-cert provider derived from the device's stored credentials.
//
// In a real app, credentials are persisted (encrypted-at-rest) after
// `bootstrapRootIdentity` runs once, then loaded on subsequent launches.
// Here we keep them in-memory for brevity.
// ---------------------------------------------------------------------------

function makeCapProvider(creds: DeviceCredentials): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: creds.capCert, devEdPrivHex: creds.device.edPriv }
    },
  }
}

// ---------------------------------------------------------------------------
// Example 1: Manual store wiring — one Zustand store per collection.
// ---------------------------------------------------------------------------

// Bootstrap once at app startup and keep the credentials.
const credentialsPromise = bootstrapRootIdentity("correct-horse-battery-staple")

async function makeClient(): Promise<{ client: StarfishClient; creds: DeviceCredentials }> {
  const creds = await credentialsPromise
  const client = new StarfishClient({
    baseUrl: "https://api.example.com/v1",
    capProvider: makeCapProvider(creds),
  })
  return { client, creds }
}

// Create a store lazily so we can await the bootstrap.
const settingsStoreInit = makeClient().then(({ client, creds }) =>
  createStarfishStore({
    name: "settings",
    syncManager: new SyncManager({
      client,
      pullPath: `/pull/users/${creds.userId}/settings`,
      pushPath: `/push/users/${creds.userId}/settings`,
      logger: consoleSyncLogger,
    }),
  }),
)

// Cross-tab sync — call this once your store is ready.
settingsStoreInit.then((store) => {
  setupCrossTabSync(store, "settings")
})

// ---------------------------------------------------------------------------
// Example 2: useSyncInit — single-call lifecycle for one collection.
//
// `useSyncInit` builds the client + SyncManager + Zustand store internally
// and tears them down on unmount or config change. Pass null to disable.
// ---------------------------------------------------------------------------

export function SyncedApp({ creds }: { creds: DeviceCredentials | null }) {
  // Memoize the capProvider so we don't re-init on every render.
  const config = useMemo(() => {
    if (!creds) return null
    return {
      serverUrl: "https://api.example.com/v1",
      capProvider: makeCapProvider(creds),
      pullPath: `/pull/users/${creds.userId}/data`,
      pushPath: `/push/users/${creds.userId}/data`,
      storeName: "user-data",
      storage: false as const,
      onConflict: createUnionMerge(),
      logger: consoleSyncLogger,
      onData: (data: Record<string, unknown>) => {
        console.log("Received data from server:", data)
      },
    }
  }, [creds])

  const store = useSyncInit(config)
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
// Example 3: Theme badge component bound to a manually-created store.
//
// Use the `data` selector to limit re-renders to a single field.
// ---------------------------------------------------------------------------

export function ThemeBadge({
  store,
}: {
  store: Awaited<typeof settingsStoreInit>
}) {
  const theme = useStarfishData(store, (d) => d.theme as string | undefined)
  return <span>{theme ?? "default"}</span>
}

export function Settings({
  store,
}: {
  store: Awaited<typeof settingsStoreInit>
}) {
  const { data, syncing, pull, set } = useStarfish(store)

  useEffect(() => {
    pull()
  }, [pull])

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {(data.theme as string) ?? "default"}
    </button>
  )
}

// ---------------------------------------------------------------------------
// Connectivity listener (browser).
// ---------------------------------------------------------------------------

export function useConnectivity(store: Awaited<typeof settingsStoreInit>) {
  useEffect(() => {
    const setOnline = (online: boolean) => store.getState().setOnline(online)
    const onOnline = () => setOnline(true)
    const onOffline = () => setOnline(false)
    window.addEventListener("online", onOnline)
    window.addEventListener("offline", onOffline)
    return () => {
      window.removeEventListener("online", onOnline)
      window.removeEventListener("offline", onOffline)
    }
  }, [store])
}
