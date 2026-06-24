---
sidebar_position: 5
---

# Schema Versioning

When your sync document format evolves across app versions, you need a migration strategy so older documents are upgraded on pull.

> **Prerequisites:** [SyncManager](/client-core/sync-manager), [Integration Patterns](/integration-operations/integration-patterns)

## The Problem

App v1 syncs documents shaped like `{ tasks: [...], version: 1 }`. App v2 renames `tasks` to `items` and adds a `tags` field. A user with v2 pulls a v1 document from the server — the app must migrate it.

## Version Field

Include a `_schemaVersion` field in every sync document:

```ts
interface SyncDocument {
  _schemaVersion: number
  timestamp: string
  items: Item[]
  tags: Tag[]
}

const CURRENT_VERSION = 2

function createSyncDocument(): SyncDocument {
  return {
    _schemaVersion: CURRENT_VERSION,
    timestamp: new Date().toISOString(),
    items: getItems(),
    tags: getTags(),
  }
}
```

## Migration on Pull

After pulling, check the version and apply migrations before using the data:

```ts
await sync.pull()
const data = sync.getData()

const migrated = migrateIfNeeded(data)
restoreFromSync(migrated)
```

### Migration Function

```ts
const CURRENT_VERSION = 2

function migrateIfNeeded(data: Record<string, unknown>): Record<string, unknown> {
  const version = (data._schemaVersion as number) ?? 1

  if (version > CURRENT_VERSION) {
    throw new Error(
      `Document version ${version} is newer than app version ${CURRENT_VERSION}. Please update the app.`
    )
  }

  let migrated = { ...data }

  if (version < 2) {
    migrated = migrateV1toV2(migrated)
  }
  // Add future migrations here:
  // if (version < 3) migrated = migrateV2toV3(migrated)

  return migrated
}
```

### Migration Example: v1 to v2

```ts
function migrateV1toV2(data: Record<string, unknown>): Record<string, unknown> {
  const migrated = { ...data }

  // Rename field
  if ("tasks" in migrated) {
    migrated.items = migrated.tasks
    delete migrated.tasks
  }

  // Add new field with default
  if (!("tags" in migrated)) {
    migrated.tags = []
  }

  // Rename values within arrays
  const items = migrated.items as Array<Record<string, unknown>> ?? []
  migrated.items = items.map((item) => ({
    ...item,
    status: item.status === "todo" ? "pending" : item.status,
  }))

  migrated._schemaVersion = 2
  return migrated
}
```

## Migration Chain

Migrations run sequentially from the document's version to the current version:

```
v1 document → migrateV1toV2() → migrateV2toV3() → v3 document
```

Each migration is responsible for exactly one version step. This keeps migrations small and testable.

## Forward Compatibility

When a newer app pushes a document that an older app doesn't understand:

- **Check version**: if `_schemaVersion > CURRENT_VERSION`, show an "update required" message
- **Ignore unknown fields**: don't crash on unrecognized keys — just pass them through
- **Use optional fields**: new fields should have defaults so older versions can omit them

## Interaction with Encryption

Migrations run **after** decryption. The `SyncManager` handles decryption transparently — by the time you call `sync.getData()`, you have the plaintext document ready for migration.

```
Server → encrypted blob → SyncManager.pull() → decrypted data → migrateIfNeeded() → app
```

## Interaction with Conflict Resolution

If your conflict resolver references specific fields, ensure it handles both old and new schemas. Two approaches:

### Migrate before merge

Run migrations on both local and remote data before conflict resolution:

```ts
const sync = new SyncManager({
  client, pullPath, pushPath,
  onConflict: (local, remote) => {
    const migratedLocal = migrateIfNeeded(local)
    const migratedRemote = migrateIfNeeded(remote)
    return mergeDocuments(migratedLocal, migratedRemote)
  },
})
```

### Version-aware resolver

Check the version and adapt the merge strategy:

```ts
onConflict: (local, remote) => {
  const localV = (local._schemaVersion as number) ?? 1
  const remoteV = (remote._schemaVersion as number) ?? 1

  // If versions differ, prefer the newer one
  if (localV !== remoteV) {
    return localV > remoteV ? local : remote
  }

  return mergeDocuments(local, remote)
}
```

## Testing Migrations

Write migration tests with fixture data for each version:

```ts
test("v1 to v2: renames tasks to items", () => {
  const v1 = {
    _schemaVersion: 1,
    tasks: [{ id: "1", title: "Test", status: "todo" }],
  }
  const v2 = migrateV1toV2(v1)

  expect(v2._schemaVersion).toBe(2)
  expect(v2.items).toHaveLength(1)
  expect(v2.tasks).toBeUndefined()
  expect((v2.items as any[])[0].status).toBe("pending")
})
```

## Next Steps

- [Integration Patterns](/integration-operations/integration-patterns) — the backup document pattern that schema versioning builds on
- [Conflict Resolution](/client-core/conflict-resolution) — version-aware merge strategies
