/**
 * Starfish + Legend State React example.
 *
 * Install:
 *   npm install @starfish/client @legendapp/state
 */

import { useEffect } from "react"
import { observer, useSelector } from "@legendapp/state/react"
import { StarfishClient, SyncManager } from "@starfish/client"
import { createStarfishObservable } from "@starfish/client/legend"

// ---------------------------------------------------------------------------
// Setup (run once at app startup)
// ---------------------------------------------------------------------------

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
})

// One observable per collection — each syncs independently
const settingsStore = createStarfishObservable({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
  }),
})

const notesStore = createStarfishObservable({
  name: "notes",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/notes",
    pushPath: "/push/users/abc/notes",
    encryptionSecret: "user-secret",
    encryptionSalt: "user-abc",
  }),
})

// ---------------------------------------------------------------------------
// Components — wrap with observer() to auto-subscribe to observables
// ---------------------------------------------------------------------------

export const Settings = observer(function Settings() {
  const { state, pull, set } = settingsStore

  useEffect(() => {
    pull()
  }, [])

  const data = state.data.get()
  const syncing = state.syncing.get()

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {data.theme as string ?? "default"}
    </button>
  )
})

export const Notes = observer(function Notes() {
  const { state, pull, set, flush } = notesStore

  useEffect(() => {
    pull()
  }, [])

  const data = state.data.get()
  const syncing = state.syncing.get()
  const error = state.error.get()
  const notes = (data.items ?? []) as string[]

  return (
    <div>
      {error && <p style={{ color: "red" }}>{error}</p>}
      <ul>
        {notes.map((note, i) => (
          <li key={i}>{note}</li>
        ))}
      </ul>
      <button
        onClick={() =>
          set((d) => ({
            ...d,
            items: [...((d.items as string[]) ?? []), "new note"],
          }))
        }
      >
        Add note
      </button>
      <button disabled={syncing} onClick={flush}>
        {syncing ? "Syncing…" : "Save"}
      </button>
    </div>
  )
})

// Fine-grained subscription — only re-renders when theme changes
export function ThemeBadge() {
  const theme = useSelector(() => settingsStore.state.data.get().theme as string)
  return <span>{theme}</span>
}

// ---------------------------------------------------------------------------
// Connectivity listener (browser)
// ---------------------------------------------------------------------------

export function useConnectivity() {
  useEffect(() => {
    const stores = [settingsStore, notesStore]
    const setOnline = (online: boolean) =>
      stores.forEach((s) => s.setOnline(online))

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
