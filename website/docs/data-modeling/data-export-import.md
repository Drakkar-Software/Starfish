---
sidebar_position: 6
---

# Data Export / Import

Export synced data for backups, GDPR compliance, or account migration. Import data into a new account or device. All patterns work with or without encryption.

> **Prerequisites:** [SyncManager](/client-core/sync-manager), [Encryption](/encryption-identity/encryption), [Integration Patterns](/integration-operations/integration-patterns)

## Built-In Export/Import Helpers

Since v1.5.0, the SDK ships built-in export/import utilities:

```ts
import { exportData, importData, exportToBlob } from "@drakkar.software/starfish-client"

// Export to JSON string
const json = exportData(data, { format: "json", pretty: true })

// Export to CSV (top-level keys become columns)
const csv = exportData(data, { format: "csv" })

// Export to downloadable Blob
const blob = exportToBlob(data, { format: "json" })
const url = URL.createObjectURL(blob)

// Import from JSON string
const imported = importData(jsonString)

// Import from CSV
const importedCsv = importData(csvString, "csv")
```

> **Note:** CSV export flattens top-level keys into a single row. Nested objects/arrays are JSON-encoded in their cells. CSV import only reads the first data row after the header.

## Exporting Data

### From a Zustand store

The store holds decrypted data in memory. Read it and trigger a download:

```ts
import type { StoreApi } from "zustand/vanilla"
import type { StarfishStore } from "@drakkar.software/starfish-client/zustand"

function exportFromStore(store: StoreApi<StarfishStore>, filename: string) {
  const { data } = store.getState()
  const json = JSON.stringify(data, null, 2)
  const blob = new Blob([json], { type: "application/json" })
  const url = URL.createObjectURL(blob)

  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// Usage
exportFromStore(settingsStore, "settings-export.json")
```

### From SyncManager directly

If you're not using a state binding, pull first then read:

```ts
await sync.pull()
const data = sync.getData()
const json = JSON.stringify(data, null, 2)
```

## Export with Encryption

### Exporting decrypted data

When `SyncManager` has encryption configured, `getData()` and `store.getState().data` already return **decrypted** data. The export examples above produce plaintext JSON — no extra steps needed.

### Exporting the encrypted blob

To export the raw encrypted data (e.g., for backup without exposing the key), bypass `SyncManager` and use `StarfishClient` directly:

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: { getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }) },
})

// This returns the raw server data, including { _encrypted: "...", _epoch: N }
const result = await client.pull(`/pull/users/${userId}/notes`)
const encryptedJson = JSON.stringify(result.data, null, 2)
```

### Re-encrypting for sharing

In v3 the typical "share" flow is to add the recipient's X25519 pubkey to
the collection's keyring rather than re-encrypting documents:

```ts
import {
  addCollectionRecipient,
  type RecipientRef,
} from "@drakkar.software/starfish-client"

const recipient: RecipientRef = { subKem: bobDeviceKemPubHex }
await addCollectionRecipient(client, "notes", recipient, {
  edPriv: creds.device.edPriv,
  edPub: creds.device.edPub,
  kemPriv: creds.device.kemPriv,
})
// Bob can now decrypt every document under the current epoch.
```

If you need a one-off re-encrypt under a separate CEK (e.g., to hand a
single dump to an external party without modifying the live keyring),
build a second keyring + encryptor for the external recipient and re-seal
each document. See [23. Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated)
for the keyring lifecycle.

## Importing Data

Read a JSON file, validate it, and push to the store:

```ts
async function importToStore(
  store: StoreApi<StarfishStore>,
  file: File,
) {
  const text = await file.text()
  const data = JSON.parse(text) as Record<string, unknown>

  // Basic validation
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    throw new Error("Import file must contain a JSON object")
  }

  // Push to store — marks dirty and auto-flushes to server
  store.getState().set(() => data)
}
```

### With schema validation

Check the schema version before importing to avoid loading incompatible data:

```ts
async function importWithValidation(
  store: StoreApi<StarfishStore>,
  file: File,
  expectedVersion: number,
) {
  const text = await file.text()
  const data = JSON.parse(text) as Record<string, unknown>

  const version = (data._schemaVersion as number) ?? 1
  if (version > expectedVersion) {
    throw new Error(
      `Import file uses schema v${version}, but this app supports up to v${expectedVersion}. ` +
      `Update the app before importing.`
    )
  }

  // Run migrations if needed (see Schema Versioning)
  const migrated = migrateIfNeeded(data, expectedVersion)
  store.getState().set(() => migrated)
}
```

See [Schema Versioning](/data-modeling/schema-versioning) for the `migrateIfNeeded` implementation and [Pre-Push Validation](/integration-operations/integration-patterns#pre-push-validation) for additional validation patterns.

### React file input

```tsx
function ImportButton({ store }: { store: StoreApi<StarfishStore> }) {
  const handleFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      await importToStore(store, file)
    } catch (err) {
      alert(`Import failed: ${(err as Error).message}`)
    }
  }

  return <input type="file" accept=".json" onChange={handleFile} />
}
```

## GDPR Data Export

Export all user data across multiple collections into a single bundle:

```ts
interface ExportBundle {
  _exportVersion: 1
  _exportedAt: string
  collections: Record<string, {
    data: Record<string, unknown>
    schemaVersion?: number
  }>
}

async function exportAllUserData(
  managers: Record<string, SyncManager>,
): Promise<ExportBundle> {
  const collections: ExportBundle["collections"] = {}

  for (const [name, sync] of Object.entries(managers)) {
    await sync.pull()
    const data = sync.getData()
    collections[name] = {
      data,
      schemaVersion: (data._schemaVersion as number) ?? undefined,
    }
  }

  return {
    _exportVersion: 1,
    _exportedAt: new Date().toISOString(),
    collections,
  }
}

// Usage
const bundle = await exportAllUserData({
  settings: settingsSync,
  notes: notesSync,
  tasks: tasksSync,
})

const json = JSON.stringify(bundle, null, 2)
// Trigger download...
```

The `_exportVersion` field lets you evolve the export format independently from individual collection schemas.

## Account Migration

Move data from one v3 account to another by pulling with the old user's
encryptor and pushing with the new user's encryptor:

```ts
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
  createKeyringEncryptor,
  type Keyring,
} from "@drakkar.software/starfish-client"

async function migrateCollection(
  oldClient: StarfishClient,
  newClient: StarfishClient,
  oldEnc: Awaited<ReturnType<typeof createKeyringEncryptor>>,
  newEnc: Awaited<ReturnType<typeof createKeyringEncryptor>>,
  oldPath: string,
  newPath: string,
) {
  // Pull from old account, decrypt with old encryptor.
  const oldSync = new SyncManager({
    client: oldClient,
    pullPath: `/pull/${oldPath}`,
    pushPath: `/push/${oldPath}`,
    encryptor: oldEnc,
  })
  await oldSync.pull()
  const data = oldSync.getData()

  // Push to the new account's path, encrypted under the new keyring.
  const newSync = new SyncManager({
    client: newClient,
    pullPath: `/pull/${newPath}`,
    pushPath: `/push/${newPath}`,
    encryptor: newEnc,
  })
  await newSync.push(data)
}

// Usage
const oldCreds = await loadOldCreds()         // your existing persisted DeviceCredentials
const newCreds = await bootstrapRootIdentity(newPassphrase)

const oldClient = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: { getCap: async () => ({ cap: oldCreds.capCert, devEdPrivHex: oldCreds.device.edPriv }) },
})
const newClient = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  capProvider: { getCap: async () => ({ cap: newCreds.capCert, devEdPrivHex: newCreds.device.edPriv }) },
})

const collections = ["settings", "notes", "tasks"]
for (const name of collections) {
  const oldKr = (await oldClient.pull(`${name}/_keyring`)).data as Keyring
  const newKr = (await newClient.pull(`${name}/_keyring`)).data as Keyring
  const oldEnc = await createKeyringEncryptor(oldKr, {
    kemPubHex: oldCreds.device.kemPub,
    kemPrivHex: oldCreds.device.kemPriv,
  })
  const newEnc = await createKeyringEncryptor(newKr, {
    kemPubHex: newCreds.device.kemPub,
    kemPrivHex: newCreds.device.kemPriv,
  })
  await migrateCollection(
    oldClient,
    newClient,
    oldEnc,
    newEnc,
    `users/${oldCreds.userId}/${name}`,
    `users/${newCreds.userId}/${name}`,
  )
}
```

**Note:** the old account's data remains on the server. Server-side cleanup (deletion) is a separate operation not covered by the client SDK.

## Next Steps

- [Encryption](/encryption-identity/encryption) — encryption details for export
- [Schema Versioning](/data-modeling/schema-versioning) — versioning exported data
- [Multi-Document Architecture](/data-modeling/multi-document-architecture) — managing multiple collections
