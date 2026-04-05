/**
 * Starfish + Zustand React example.
 *
 * Install:
 *   npm install @starfish/client zustand
 *   npm install immer  # optional, for draft-based mutations
 */

import { useEffect } from "react"
import { useStore } from "zustand"
import { StarfishClient, SyncManager } from "@starfish/client"
import { createStarfishStore } from "@starfish/client/zustand"

// ---------------------------------------------------------------------------
// Setup (run once at app startup)
// ---------------------------------------------------------------------------

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${await getToken()}` }),
})

// One store per collection — each syncs independently
const settingsStore = createStarfishStore({
  name: "settings",
  syncManager: new SyncManager({
    client,
    pullPath: "/pull/users/abc/settings",
    pushPath: "/push/users/abc/settings",
  }),
})

const notesStore = createStarfishStore({
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
// Components
// ---------------------------------------------------------------------------

export function Settings() {
  const { data, syncing, pull, set } = useStore(settingsStore)

  useEffect(() => {
    pull()
  }, [])

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {data.theme as string ?? "default"}
    </button>
  )
}

export function Notes() {
  const { data, syncing, error, pull, set, flush } = useStore(notesStore)

  useEffect(() => {
    pull()
  }, [])

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
}

// Subscribe to specific fields to avoid re-renders
export function ThemeBadge() {
  const theme = useStore(settingsStore, (s) => s.data.theme)
  return <span>{theme as string}</span>
}

// ---------------------------------------------------------------------------
// Connectivity listener (browser)
// ---------------------------------------------------------------------------

export function useConnectivity() {
  useEffect(() => {
    const stores = [settingsStore, notesStore]
    const setOnline = (online: boolean) =>
      stores.forEach((s) => s.getState().setOnline(online))

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
