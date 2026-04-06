# Data Export / Import

Export synced data for backups, GDPR compliance, or account migration. Import data into a new account or device. All patterns work with or without encryption.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Encryption](04-encryption.md), [Integration Patterns](09-integration-patterns.md)

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
  auth: async () => ({ Authorization: `Bearer ${token}` }),
})

// This returns the raw server data, including { _encrypted: "..." }
const result = await client.pull(`/pull/users/${userId}/notes`)
const encryptedJson = JSON.stringify(result.data, null, 2)
```

### Re-encrypting for sharing

Decrypt with the original key, then encrypt with a new key:

```ts
import { createEncryptor } from "@drakkar.software/starfish-client"

const original = createEncryptor(originalSecret, originalSalt)
const shared = createEncryptor(sharedSecret, sharedSalt)

// Pull the raw encrypted blob
const result = await client.pull(`/pull/users/${userId}/notes`)
const decrypted = await original.decrypt(result.data)
const reEncrypted = await shared.encrypt(decrypted)
```

See [Identity & Key Derivation](11-identity-key-derivation.md#sharing-encrypted-data) for key sharing patterns.

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

See [Schema Versioning](12-schema-versioning.md) for the `migrateIfNeeded` implementation and [Pre-Push Validation](09-integration-patterns.md#pre-push-validation) for additional validation patterns.

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

Move data from one account to another by pulling with old credentials and pushing with new ones:

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"

async function migrateCollection(
  oldClient: StarfishClient,
  newClient: StarfishClient,
  pullPath: string,
  pushPath: string,
  encryptionSecret?: string,
  oldSalt?: string,
  newSalt?: string,
) {
  // Pull from old account (decrypt with old salt)
  const oldSync = new SyncManager({
    client: oldClient,
    pullPath,
    pushPath,
    encryptionSecret,
    encryptionSalt: oldSalt,
  })
  await oldSync.pull()
  const data = oldSync.getData()

  // Push to new account (encrypt with new salt)
  const newSync = new SyncManager({
    client: newClient,
    pullPath,
    pushPath,
    encryptionSecret,
    encryptionSalt: newSalt,
  })
  await newSync.push(data)
}

// Usage
const oldClient = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${oldToken}` }),
})

const newClient = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${newToken}` }),
})

const collections = ["settings", "notes", "tasks"]
for (const name of collections) {
  await migrateCollection(
    oldClient,
    newClient,
    `/pull/users/${oldUserId}/${name}`,
    `/push/users/${newUserId}/${name}`,
    encryptionSecret,
    oldUserId, // old salt for decryption
    newUserId, // new salt for encryption
  )
}
```

**Note:** the old account's data remains on the server. Server-side cleanup (deletion) is a separate operation not covered by the client SDK.

## Next Steps

- [Encryption](04-encryption.md) — encryption details for export
- [Schema Versioning](12-schema-versioning.md) — versioning exported data
- [Multi-Document Architecture](18-multi-document-architecture.md) — managing multiple collections
