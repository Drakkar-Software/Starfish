---
sidebar_position: 4
---

# Multi-Document Architecture

When to use one sync document versus many, how to design URL paths, and strategies for partitioning data across documents. This expands on the [Multiple Collections](/integration-operations/integration-patterns#multiple-collections) section.

> **Prerequisites:** [SyncManager](/client-core/sync-manager), [Integration Patterns](/integration-operations/integration-patterns)

## One Document vs. Many

Use this decision table to determine how to split your data:

| Factor | One document | Multiple documents |
|--------|-------------|-------------------|
| **Size** | Small (< 100 KB) | Large or growing unboundedly |
| **Access pattern** | All data needed at once | Different screens use different data |
| **Update frequency** | Everything changes together | Some parts change rarely |
| **Conflict frequency** | Low (few concurrent editors) | High (split reduces conflicts) |
| **Permissions** | Same access for all fields | Different access per section |
| **Offline** | Entire dataset available offline | Only sync what's needed |

**Rules of thumb:**

- A "settings" object with 20 keys → **one document**
- A list of 10,000 notes → **one document per note** (or chunked)
- User profile + preferences + theme → **one document** (small, read together)
- Tasks + comments + attachments → **separate documents** (different update rates, different sizes)

## URL Path Design

Starfish uses URL paths to identify sync endpoints. Design them like REST resources:

### Flat (one document per feature)

```
/pull/users/{userId}/settings
/pull/users/{userId}/notes
/pull/users/{userId}/tasks
```

Each path maps to one `SyncManager`. Good for documents that are always loaded together.

### Nested (one document per entity)

```
/pull/users/{userId}/notes/{noteId}
/pull/users/{userId}/projects/{projectId}
```

Each entity gets its own sync endpoint. Good when entities are large or independently accessed.

### Factory function

Create `SyncManager` instances dynamically for per-entity documents:

```ts
import {
  StarfishClient,
  SyncManager,
  type Encryptor,
} from "@drakkar.software/starfish-client"

function createNoteSyncManager(
  client: StarfishClient,
  userId: string,
  noteId: string,
  encryptor?: Encryptor,
): SyncManager {
  return new SyncManager({
    client,
    pullPath: `/pull/users/${userId}/notes/${noteId}`,
    pushPath: `/push/users/${userId}/notes/${noteId}`,
    encryptor,
  })
}

// The encryptor is shared across every per-note manager — it's built from
// the collection's single `_keyring` document (see 23-multi-recipient-delegated.md).
const noteSync = createNoteSyncManager(client, userId, "note-42", notesEncryptor)
await noteSync.pull()
```

## Document Size Limits

There's no hard protocol limit, but keep documents **under 1 MB** for good performance:

| Size | Performance | Recommendation |
|------|-------------|----------------|
| < 50 KB | Excellent | Most settings/preferences |
| 50–200 KB | Good | Lists with hundreds of items |
| 200 KB–1 MB | Acceptable | Compress if possible |
| > 1 MB | Slow sync, high bandwidth | Split into multiple documents |

Factors that increase document size:
- **Encryption** adds ~33% overhead (base64 encoding of the encrypted blob)
- **Tombstones** from [soft delete](/integration-operations/integration-patterns#soft-delete--tombstone-pattern) accumulate over time — schedule cleanup
- **Local history** snapshots (if stored in the same document) can grow unboundedly

See [Compression](/integration-operations/integration-patterns#compression) for reducing payload size.

## Partitioning Strategies

### By feature

One document per feature area. Simplest approach:

```ts
const settingsSync = new SyncManager({ client, pullPath: "/pull/.../settings", pushPath: "/push/.../settings" })
const notesSync = new SyncManager({ client, pullPath: "/pull/.../notes", pushPath: "/push/.../notes" })
const tasksSync = new SyncManager({ client, pullPath: "/pull/.../tasks", pushPath: "/push/.../tasks" })
```

### By access frequency

Separate data the user sees on every screen from data loaded on demand:

```ts
// Always loaded (small, used everywhere)
const coreSync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/core`,   // profile + prefs + theme
  pushPath: `/push/users/${userId}/core`,
})

// Loaded on demand (large, specific screens)
const archiveSync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/archive`, // old completed tasks
  pushPath: `/push/users/${userId}/archive`,
})
```

Pull `coreSync` on app start. Pull `archiveSync` only when the user navigates to the archive screen.

### By update frequency

Separate hot data (changes often) from cold data (rarely changes):

```ts
// Hot: tasks change every minute
const tasksSync = new SyncManager({ ... })

// Cold: settings change once a month
const settingsSync = new SyncManager({ ... })
```

This reduces conflicts — the tasks document sees more concurrent edits, but settings rarely conflict because they're updated infrequently.

### By permissions

Separate public data from private data:

```ts
// Public profile (readable by others)
const profileSync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/profile`,
  pushPath: `/push/users/${userId}/profile`,
})

// Private notes (encrypted, owner-only via per-collection keyring)
const notesKeyring = (await client.pull(`users/${userId}/notes/_keyring`)).data as Keyring
const notesEncryptor = await createKeyringEncryptor(notesKeyring, {
  kemPubHex: creds.device.kemPub,
  kemPrivHex: creds.device.kemPriv,
})
const notesSync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/notes`,
  pushPath: `/push/users/${userId}/notes`,
  encryptor: notesEncryptor,
})
```

## Cross-Document References

When entities in one document reference entities in another, use stable IDs:

```ts
// Tasks document
{
  items: [
    { id: "task-1", title: "Design API", tagIds: ["tag-a", "tag-b"] },
    { id: "task-2", title: "Write tests", tagIds: ["tag-a"] },
  ]
}

// Tags document (separate sync)
{
  items: [
    { id: "tag-a", name: "Backend", color: "blue" },
    { id: "tag-b", name: "Design", color: "green" },
  ]
}
```

### Resolving references

References can become stale if one document is synced but not the other. Resolve at read time and handle missing references gracefully:

```ts
function resolveTaskTags(
  task: { tagIds: string[] },
  tagsById: Map<string, { name: string; color: string }>,
) {
  return task.tagIds
    .map((id) => tagsById.get(id))
    .filter(Boolean) // Skip missing tags (not yet synced)
}
```

This "eventual references" approach means the UI may briefly show incomplete data until both documents are pulled. This is usually acceptable — the user sees "3 of 4 tags loaded" rather than an error.

## Dynamic Document Creation

When users create entities that each need their own sync document (e.g., projects, notebooks), manage `SyncManager` instances dynamically:

```ts
const activeSyncs = new Map<string, SyncManager>()

function openProject(projectId: string): SyncManager {
  if (activeSyncs.has(projectId)) {
    return activeSyncs.get(projectId)!
  }

  // The encryptor is shared across every per-project manager — it comes from
  // the projects collection's single `_keyring` document.
  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${userId}/projects/${projectId}`,
    pushPath: `/push/users/${userId}/projects/${projectId}`,
    encryptor: projectsEncryptor,
  })

  activeSyncs.set(projectId, sync)
  return sync
}

function closeProject(projectId: string) {
  activeSyncs.delete(projectId)
}
```

### Lifecycle

When a project is deleted, stop syncing and clean up:

```ts
function deleteProject(projectId: string) {
  // 1. Stop syncing
  closeProject(projectId)

  // 2. Update the project list (a separate sync document)
  projectListStore.getState().set((data) => ({
    ...data,
    projects: (data.projects as any[]).map((p) =>
      p.id === projectId ? { ...p, _deletedAt: Date.now() } : p
    ),
  }))

  // Server-side data cleanup is outside the client SDK scope
}
```

## Aggregating Multiple Documents

When your UI needs a unified view across multiple sync documents, subscribe to all stores and merge:

```ts
import { useStore } from "zustand"

function useAllTasks() {
  const personalTasks = useStore(personalTasksStore, (s) => s.data.items ?? [])
  const workTasks = useStore(workTasksStore, (s) => s.data.items ?? [])

  return [...(personalTasks as any[]), ...(workTasks as any[])]
    .sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
}
```

For sync status across multiple stores, see [Offline & Connectivity — Multiple stores](/state-offline/offline-connectivity#multiple-stores).

## Next Steps

- [Integration Patterns](/integration-operations/integration-patterns) — integration layer, compression, multiple collections
- [Data Export / Import](/data-modeling/data-export-import) — exporting multiple documents
- [Schema Versioning](/data-modeling/schema-versioning) — versioning per document
