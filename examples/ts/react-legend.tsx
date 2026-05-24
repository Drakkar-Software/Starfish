/**
 * Starfish v3.0 + Legend State + React.
 *
 * Demonstrates wiring a v3 cap-cert provider into a Legend-backed observable.
 *
 * Install:
 *   npm install @drakkar.software/starfish-client @legendapp/state react
 */

import { useEffect } from "react"
import { observer, useSelector } from "@legendapp/state/react"
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
  consoleSyncLogger,
  createKeyringEncryptor,
  createKeyring,
  type Encryptor,
  type StarfishCapProvider,
  type DeviceCredentials,
  type Keyring,
} from "@drakkar.software/starfish-client"
import { createStarfishObservable } from "@drakkar.software/starfish-client/legend"

function makeCapProvider(creds: DeviceCredentials): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: creds.capCert, devEdPrivHex: creds.device.edPriv }
    },
  }
}

// ---------------------------------------------------------------------------
// Setup — bootstrap identity once, then build stores per collection.
// ---------------------------------------------------------------------------

const setupPromise = (async () => {
  const creds = await bootstrapRootIdentity("correct-horse-battery-staple")

  const client = new StarfishClient({
    baseUrl: "https://api.example.com/v1",
    capProvider: makeCapProvider(creds),
  })

  // Plaintext per-user settings collection.
  const settingsStore = createStarfishObservable({
    name: "settings",
    syncManager: new SyncManager({
      client,
      pullPath: `/pull/users/${creds.userId}/settings`,
      pushPath: `/push/users/${creds.userId}/settings`,
      logger: consoleSyncLogger,
    }),
  })

  // Encrypted notes collection — build a keyring with just our own device,
  // then create a KeyringEncryptor for the SyncManager.
  const { keyring } = await createKeyring(
    { edPrivHex: creds.device.edPriv, edPubHex: creds.device.edPub },
    [{ subKemHex: creds.device.kemPub }],
  )
  const encryptor = (await createKeyringEncryptor(
    keyring,
    {
      kemPubHex: creds.device.kemPub,
      kemPrivHex: creds.device.kemPriv,
    },
    { trustedAdders: [creds.device.edPub] },
  )) as unknown as Encryptor

  const notesStore = createStarfishObservable({
    name: "notes",
    syncManager: new SyncManager({
      client,
      pullPath: `/pull/users/${creds.userId}/notes`,
      pushPath: `/push/users/${creds.userId}/notes`,
      encryptor, // v3: KeyringEncryptor — replaces v2 encryptionSecret/Salt
      logger: consoleSyncLogger,
    }),
  })

  return { settingsStore, notesStore, keyring, creds }
})()

// In a real app, await this once at startup before rendering components.
// Demonstration only — components below assume the stores are resolved.
let settingsStore: Awaited<typeof setupPromise>["settingsStore"] | null = null
let notesStore: Awaited<typeof setupPromise>["notesStore"] | null = null
let initializedKeyring: Keyring | null = null
setupPromise.then((s) => {
  settingsStore = s.settingsStore
  notesStore = s.notesStore
  initializedKeyring = s.keyring
  void initializedKeyring
})

// ---------------------------------------------------------------------------
// Components — wrap with observer() to auto-subscribe to observables.
// ---------------------------------------------------------------------------

export const Settings = observer(function Settings() {
  if (!settingsStore) return <p>Loading…</p>
  const { state, pull, set } = settingsStore

  useEffect(() => {
    pull()
  }, [pull])

  const data = state.data.get()
  const syncing = state.syncing.get()

  return (
    <button
      disabled={syncing}
      onClick={() => set((d) => ({ ...d, theme: "dark" }))}
    >
      Theme: {(data.theme as string) ?? "default"}
    </button>
  )
})

export const Notes = observer(function Notes() {
  if (!notesStore) return <p>Loading…</p>
  const { state, pull, set, flush } = notesStore

  useEffect(() => {
    pull()
  }, [pull])

  const data = state.data.get()
  const syncing = state.syncing.get()
  const error = state.error.get()
  const notes = (data["items"] ?? []) as string[]

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
            items: [...((d["items"] as string[]) ?? []), "new note"],
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

// Fine-grained subscription — only re-renders when theme changes.
export function ThemeBadge() {
  const theme = useSelector(() =>
    settingsStore ? (settingsStore.state.data.get()["theme"] as string | undefined) : undefined,
  )
  return <span>{theme ?? "default"}</span>
}
