# Integration Patterns

Architectural patterns for integrating Starfish into real applications. These patterns are framework-agnostic and apply to any app that syncs structured data.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Zustand](05-state-zustand.md) or [Legend State](06-state-legend.md)

## Integration Layer

When your app has its own domain stores (e.g., one store for tasks, one for settings), create a thin integration layer between them and Starfish.

```
┌────────────────┐                  ┌──────────────────┐
│  Domain Stores  │  notifySync()   │  Integration     │
│  (tasks, etc.)  │ ───────────────►│  Layer           │
│                 │ ◄── restore ──  │  (serialize /    │
└────────────────┘                  │   deserialize)   │
                                    └────────┬─────────┘
                                             │
                                    ┌────────▼─────────┐
                                    │  Starfish Store   │
                                    │  (pull / push)    │
                                    └──────────────────┘
```

**Responsibilities:**
- **Serialize**: collect domain store state into a single sync document
- **Deserialize**: on pull, restore domain stores from the sync document
- **Notify**: trigger a push when any domain store changes

```ts
// lib/sync-bridge.ts
import { createStarfishStore } from "@drakkar.software/starfish-client/zustand"

let store: StoreApi<StarfishStore> | null = null

export function initSync(syncManager: SyncManager) {
  store = createStarfishStore({ name: "app", syncManager, storage: false })

  // Subscribe to incoming remote data
  store.subscribe(
    (state) => state.data,
    (data) => {
      if (Object.keys(data).length > 0) {
        restoreFromSync(data)
      }
    },
  )
}

export function notifySync() {
  if (!store) return
  store.getState().set(() => createSyncDocument())
}

function createSyncDocument(): Record<string, unknown> {
  return {
    _schemaVersion: 1,
    timestamp: new Date().toISOString(),
    tasks: taskStore.getState().tasks,
    settings: settingsStore.getState().settings,
  }
}

function restoreFromSync(data: Record<string, unknown>) {
  taskStore.getState().setTasks(data.tasks as Task[])
  settingsStore.getState().setSettings(data.settings as Settings)
}
```

## Debounced Push

When users type or drag items, domain stores fire many rapid mutations. Debounce the sync to avoid pushing on every keystroke:

```ts
let pushTimer: ReturnType<typeof setTimeout> | null = null
const PUSH_DEBOUNCE_MS = 2000

export function notifySync() {
  if (!store) return

  // Clear any pending push
  if (pushTimer) clearTimeout(pushTimer)

  // Schedule a push after 2s of no further edits
  pushTimer = setTimeout(() => {
    store!.getState().set(() => createSyncDocument())
    pushTimer = null
  }, PUSH_DEBOUNCE_MS)
}
```

The 2-second window batches rapid mutations into a single push. Adjust the delay based on your use case — shorter for collaborative editing, longer for form-style input.

## Restore-Loop Prevention

When remote data arrives via `pull()`, you restore it into domain stores. But restoring triggers domain store subscriptions, which call `notifySync()`, which tries to push back — creating an infinite loop.

Prevent this with an `isRestoring` flag:

```ts
let isRestoring = false

export function notifySync() {
  if (!store || isRestoring) return  // guard
  // ... debounced push
}

function restoreFromSync(data: Record<string, unknown>) {
  isRestoring = true
  try {
    taskStore.getState().setTasks(data.tasks as Task[])
    settingsStore.getState().setSettings(data.settings as Settings)
  } finally {
    isRestoring = false
  }
}
```

Also set the flag when pushing, to prevent the store subscription from treating your own push as an incoming remote update:

```ts
pushTimer = setTimeout(() => {
  isRestoring = true
  store!.getState().set(() => createSyncDocument())
  isRestoring = false
}, PUSH_DEBOUNCE_MS)
```

## Backup Document Pattern

Serialize your entire app state into a single Starfish document. This provides "save/restore" semantics — the server stores one encrypted snapshot.

```ts
interface SyncDocument {
  _schemaVersion: number
  timestamp: string
  tasks: Task[]
  settings: Settings
  tags: Tag[]
}
```

**Advantages:**
- Simple — one collection to manage
- Atomic — all data is consistent at every sync point
- Works naturally with E2E encryption (one encrypted blob)

**Trade-offs:**
- No partial sync — every push sends the full document
- Larger payloads on every sync cycle
- Conflict resolution is document-level, not field-level

For large datasets or collaborative editing, consider splitting into multiple collections (one per entity type).

## Push / Pull Flow

### Push Flow

```
User action (e.g., create task)
       │
       ▼
Domain store mutation
  ├── Updates in-memory state
  ├── Writes to local persistence (DB, localStorage)
  └── Calls notifySync()
       │
       ▼
notifySync()
  └── Debounced (2s)
       │
       ▼
store.set(() => createSyncDocument())
  ├── Snapshots all domain stores
  ├── Marks dirty = true
  └── Calls flush() (if online)
       │
       ▼
SyncManager.push()
  ├── Encrypts (if enabled)
  ├── POST /push/...
  ├── 200 OK → done
  └── 409 → pull, merge, retry
```

### Pull Flow

```
pull() called (on init or explicit)
       │
       ▼
SyncManager.pull()
  ├── GET /pull/...
  ├── Decrypts (if needed)
  └── Returns data
       │
       ▼
Store subscription fires
  ├── Guard: !isRestoring
  ├── Set isRestoring = true
  ├── restoreFromSync(data)
  │     ├── Update domain stores
  │     └── Update local persistence
  └── Set isRestoring = false
```

## Soft Delete / Tombstone Pattern

In a sync system, naively removing items from arrays causes problems: when Device A deletes an item and pushes, Device B still has the item locally. On the next conflict merge, a union strategy "resurrects" the deleted item.

The solution: **never remove items from arrays**. Instead, mark them as deleted with a timestamp.

### Item schema

```ts
interface SyncItem {
  id: string
  updatedAt: number      // Date.now() at last modification
  _deletedAt?: number    // set when "deleted", undefined when alive
  [key: string]: unknown
}
```

### Domain store operations

```ts
// Create
function addTask(title: string): Task {
  const task: Task = {
    id: crypto.randomUUID(),
    title,
    updatedAt: Date.now(),
  }
  tasks.push(task)
  notifySync()
  return task
}

// Update
function updateTask(id: string, changes: Partial<Task>) {
  const task = tasks.find((t) => t.id === id)
  if (task && !task._deletedAt) {
    Object.assign(task, changes, { updatedAt: Date.now() })
    notifySync()
  }
}

// Soft delete
function deleteTask(id: string) {
  const task = tasks.find((t) => t.id === id)
  if (task) {
    task._deletedAt = Date.now()
    task.updatedAt = Date.now()  // so the deletion wins in merge
    notifySync()
  }
}
```

### Filtering in the UI

Tombstones exist in the synced data but should be invisible to users:

```ts
// Read active items only
function getActiveTasks(): Task[] {
  return tasks.filter((t) => !t._deletedAt)
}
```

### Why it works with conflict resolution

When both devices have the item and one deletes it:

1. Device A sets `_deletedAt = 1712345678, updatedAt = 1712345678`
2. Device B edits the same item: `title = "Updated", updatedAt = 1712345600`
3. On conflict merge (ID + `updatedAt`): Device A's version wins because `1712345678 > 1712345600`
4. The item stays deleted — the deletion is the most recent action

See [Conflict Resolution — Soft-delete-aware merge](07-conflict-resolution.md#soft-delete-aware-merge) for the merge implementation.

### Tombstone cleanup

Tombstones grow the document over time. Periodically prune old ones using the built-in
`pruneTombstones` utility:

```ts
import { pruneTombstones } from "@drakkar.software/starfish-client"

// Default: 30-day TTL, _deletedAt key
const cleaned = pruneTombstones(items)

// Custom TTL (ms) and a non-default deleted-at key
const cleaned2 = pruneTombstones(items, 7 * 24 * 60 * 60 * 1000, "removedAt")
```

Run this before pushing to the server. The TTL should be longer than the maximum time a device might be offline — otherwise a device that comes back after the TTL window could resurrect pruned items.

## Local History

The Starfish server stores only the latest version of each document, and `SyncManager` keeps no history. For undo/recovery, maintain a client-side snapshot stack.

### Snapshot model

```ts
interface Snapshot {
  timestamp: number
  label: string           // e.g., "before sync", "manual save"
  data: string            // JSON-serialized document
}

const MAX_SNAPSHOTS = 20
let history: Snapshot[] = []
```

### Taking snapshots

Capture snapshots at key moments — before push, after pull, or on explicit user action:

```ts
function takeSnapshot(label: string) {
  const data = JSON.stringify(createSyncDocument())
  history.push({ timestamp: Date.now(), label, data })
  if (history.length > MAX_SNAPSHOTS) {
    history = history.slice(-MAX_SNAPSHOTS)
  }
}

// Before every push
const originalNotifySync = notifySync
notifySync = () => {
  takeSnapshot("before push")
  originalNotifySync()
}

// After every pull restore
function restoreFromSync(data: Record<string, unknown>) {
  takeSnapshot("before remote restore")
  isRestoring = true
  try {
    // ... restore domain stores
  } finally {
    isRestoring = false
  }
}
```

### Restoring from history

```ts
function restoreSnapshot(index: number) {
  const snapshot = history[index]
  if (!snapshot) return

  const data = JSON.parse(snapshot.data)
  isRestoring = true
  try {
    restoreFromSync(data)
  } finally {
    isRestoring = false
  }

  // Push the restored state to sync it across devices
  notifySync()
}

function getHistory(): Array<{ timestamp: number; label: string }> {
  return history.map(({ timestamp, label }) => ({ timestamp, label }))
}
```

### Storage

For persistence across app restarts, store the history in localStorage or SQLite:

```ts
function persistHistory() {
  localStorage.setItem("sync-history", JSON.stringify(history))
}

function loadHistory() {
  const raw = localStorage.getItem("sync-history")
  if (raw) history = JSON.parse(raw)
}
```

### Trade-offs

- **Storage cost**: each snapshot is a full copy of the document. For a 50 KB document with 20 snapshots, that's ~1 MB
- **No server-side history**: restoring a snapshot and pushing it overwrites the server version. Other devices will receive the restored version on next pull
- **Granularity**: snapshots are taken at sync boundaries (before push / after pull), not on every keystroke. For finer-grained undo, implement a separate undo stack in your domain stores

## Optimistic UI with Rollback

The state bindings apply writes instantly (`set()` updates `data` before pushing). But if the push fails — network error, conflict exhaustion, server rejection — the UI shows state that never reached the server. You need a rollback strategy.

### Snapshot-based rollback

Capture the last confirmed state and restore it on failure:

```ts
let lastConfirmedData: Record<string, unknown> = {}

// After a successful pull or push, capture the confirmed state
store.subscribe(
  (state) => state.syncing,
  (syncing, prevSyncing) => {
    // Transition from syncing → not syncing
    if (prevSyncing && !syncing) {
      const { error, data } = store.getState()
      if (!error) {
        lastConfirmedData = data  // push/pull succeeded
      }
    }
  },
)
```

On error, offer the user a choice:

```tsx
function SyncErrorBanner() {
  const error = useStore(store, (s) => s.error)

  if (!error) return null

  return (
    <div>
      <p>Failed to save: {error}</p>
      <button onClick={() => store.getState().flush()}>
        Retry
      </button>
      <button onClick={() => {
        // Rollback to last confirmed state
        store.getState().set(() => lastConfirmedData)
      }}>
        Discard changes
      </button>
    </div>
  )
}
```

### Auto-rollback

For non-interactive contexts (background sync, automated flows), roll back automatically:

```ts
store.subscribe(
  (state) => state.error,
  (error) => {
    if (error) {
      console.warn("Sync failed, rolling back:", error)
      store.getState().set(() => lastConfirmedData)
    }
  },
)
```

### Trade-offs

- **Snapshot rollback** is simple but discards all local changes since the last successful sync — if the user made 10 edits and push #8 failed, edits 8-10 are lost on rollback
- For finer granularity, combine with [Local History](#local-history) to let the user pick which snapshot to restore
- In most cases, **retry is preferable to rollback** — the `dirty` flag persists, so the next `flush()` or `setOnline(true)` will retry automatically

## Sync Lifecycle Hooks

Hook into sync events for logging, analytics, snapshots, or side effects. Since the SDK doesn't expose lifecycle callbacks directly, build them by subscribing to store state transitions.

### Hook implementation

```ts
interface SyncHooks {
  onPullStart?: () => void
  onPullSuccess?: (data: Record<string, unknown>) => void
  onPullError?: (error: string) => void
  onPushStart?: () => void
  onPushSuccess?: (data: Record<string, unknown>) => void
  onPushError?: (error: string) => void
}

function attachSyncHooks(
  store: StoreApi<StarfishStore>,
  hooks: SyncHooks,
) {
  // Capture the original actions before wrapping
  const originalPull = store.getState().pull
  const originalFlush = store.getState().flush

  // Wrap pull
  store.setState({
    pull: async () => {
      hooks.onPullStart?.()
      await originalPull()
      const { error, data } = store.getState()
      if (error) hooks.onPullError?.(error)
      else hooks.onPullSuccess?.(data)
    },
  })

  // Wrap flush (also called internally by set() when online)
  store.setState({
    flush: async () => {
      hooks.onPushStart?.()
      await originalFlush()
      const { error, data } = store.getState()
      if (error) hooks.onPushError?.(error)
      else hooks.onPushSuccess?.(data)
    },
  })
}
```

### Usage

```ts
attachSyncHooks(settingsStore, {
  onPullStart: () => console.log("[sync] pulling..."),
  onPullSuccess: (data) => analytics.track("sync_pull", { keys: Object.keys(data).length }),
  onPushStart: () => takeSnapshot("before push"),
  onPushError: (err) => errorReporter.capture(new Error(`Push failed: ${err}`)),
})
```

This pairs well with [Local History](#local-history) — take a snapshot in `onPushStart` for automatic undo on failure.

> **Note:** `attachSyncHooks` replaces actions via `store.setState()`. The wrapped `flush` is picked up by `set()` because it reads from `get().flush()` at call time. Call `attachSyncHooks` once, immediately after store creation, before any sync operations.

## Pre-Push Validation

Validate the sync document before it reaches the server. This catches malformed data, oversized payloads, or incomplete forms — especially useful with E2E encryption where the server cannot inspect or validate content.

### Validation wrapper

```ts
interface ValidationRule {
  check: (data: Record<string, unknown>) => boolean
  message: string
}

const rules: ValidationRule[] = [
  {
    check: (d) => (d._schemaVersion as number) > 0,
    message: "Missing schema version",
  },
  {
    check: (d) => JSON.stringify(d).length < 5_000_000,
    message: "Document exceeds 5 MB limit",
  },
  {
    check: (d) => Array.isArray(d.tasks),
    message: "Tasks must be an array",
  },
]

function validateBeforePush(data: Record<string, unknown>): string | null {
  for (const rule of rules) {
    if (!rule.check(data)) return rule.message
  }
  return null
}
```

### Integration with the sync bridge

Validate in `notifySync()` before calling `set()`:

```ts
export function notifySync() {
  if (!store || isRestoring) return

  if (pushTimer) clearTimeout(pushTimer)

  pushTimer = setTimeout(() => {
    const doc = createSyncDocument()
    const error = validateBeforePush(doc)
    if (error) {
      console.error("Sync validation failed:", error)
      return  // don't push invalid data
    }

    isRestoring = true
    store!.getState().set(() => doc)
    isRestoring = false
    pushTimer = null
  }, PUSH_DEBOUNCE_MS)
}
```

### Validation on pull

Validate remote data after pull too — it could be from an older app version or corrupted:

```ts
function restoreFromSync(data: Record<string, unknown>) {
  // Reject clearly invalid remote data
  if (!data || typeof data !== "object") {
    console.error("Received invalid sync data, ignoring")
    return
  }

  // Check schema version
  const version = data._schemaVersion as number
  if (version > CURRENT_VERSION) {
    console.warn("Remote data is from a newer app version — update required")
    return
  }

  isRestoring = true
  try {
    const migrated = migrateIfNeeded(data)
    taskStore.getState().setTasks(migrated.tasks as Task[])
    settingsStore.getState().setSettings(migrated.settings as Settings)
  } finally {
    isRestoring = false
  }
}
```

## Compression

For apps with large sync documents, compress the payload before encryption to reduce bandwidth. Compression should run **before** encryption — encrypted data is incompressible.

### Where to compress

Compression is best handled in your integration layer — inside `createSyncDocument()` and `restoreFromSync()` — so the Starfish SDK only ever sees the compressed wrapper. This keeps conflict resolution, encryption, and state management unaffected:

```ts
async function createSyncDocument(): Promise<Record<string, unknown>> {
  const doc = {
    _schemaVersion: 1,
    tasks: taskStore.getState().tasks,
    settings: settingsStore.getState().settings,
  }

  // Compress large arrays as base64
  const json = JSON.stringify(doc)
  if (json.length > 100_000) {
    const compressed = await compress(new TextEncoder().encode(json))
    return {
      _compressed: true,
      _data: arrayToBase64(compressed),
    }
  }

  return doc
}

async function restoreFromSync(data: Record<string, unknown>) {
  let doc = data
  if (data._compressed) {
    const bytes = base64ToArray(data._data as string)
    const decompressed = await decompress(bytes)
    doc = JSON.parse(new TextDecoder().decode(decompressed))
  }

  isRestoring = true
  try {
    taskStore.getState().setTasks(doc.tasks as Task[])
    settingsStore.getState().setSettings(doc.settings as Settings)
  } finally {
    isRestoring = false
  }
}
```

### Compress/decompress helpers

Using the browser's built-in `CompressionStream` (available in modern browsers and Node.js 18+):

```ts
async function compress(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data])
    .stream()
    .pipeThrough(new CompressionStream("gzip"))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

async function decompress(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
```

### When to use compression

| Document size | Compression benefit | Recommendation |
|--------------|-------------------|----------------|
| < 50 KB | Negligible | Skip — adds complexity for no gain |
| 50 KB – 500 KB | 50-70% reduction | Consider if bandwidth is constrained |
| > 500 KB | 70-90% reduction | Recommended |

**Important:** Compression must happen **before** encryption. Encrypted data has maximum entropy and cannot be compressed. The flow is: serialize → compress → encrypt → push.

### Interaction with conflict resolution

The `ConflictResolver` type is synchronous — it cannot be async. Since compression is async, you **cannot** decompress inside the conflict resolver. Instead, handle compression entirely in the integration layer (`createSyncDocument` / `restoreFromSync`), so the conflict resolver always receives uncompressed data.

If you need compression **and** a custom conflict resolver, wrap the compressed blob as an opaque field that the default `deepMerge` passes through untouched:

```ts
// The sync document is { _compressed: true, _data: "base64..." }
// deepMerge treats this as a scalar — remote wins, which is fine
// Your integration layer decompresses after pull, before restoring
```

For per-item conflict resolution, compress individual arrays instead of the whole document, keeping the top-level structure mergeable.

## Multiple Collections

> For a comprehensive guide on document partitioning, URL design, and dynamic documents, see [Multi-Document Architecture](18-multi-document-architecture.md).

Use one Starfish collection per independent data domain:

```ts
// Each collection syncs independently
const settingsSync = new SyncManager({
  client, pullPath: "/pull/.../settings", pushPath: "/push/.../settings",
})

// For encrypted collections, build the encryptor from the keyring document.
// See 23-multi-recipient-delegated.md for the full keyring lifecycle.
const tasksKeyring = (await client.pull(`tasks/_keyring`)).data as Keyring
const tasksEncryptor = await createKeyringEncryptor(tasksKeyring, {
  kemPubHex: creds.device.kemPub,
  kemPrivHex: creds.device.kemPriv,
})
const tasksSync = new SyncManager({
  client, pullPath: "/pull/.../tasks", pushPath: "/push/.../tasks",
  encryptor: tasksEncryptor,
})
```

**When to use one document:**
- Small datasets (< 100 KB)
- All data changes together
- Atomic consistency is important

**When to use multiple collections:**
- Large or growing datasets
- Independent data domains with different update frequencies
- Different encryption requirements per domain
- Per-collection access control on the server

## Next Steps

- [Schema Versioning](12-schema-versioning.md) — evolving the sync document format
- [Conflict Resolution](07-conflict-resolution.md) — custom merge strategies for complex documents
- [Testing Strategies](13-testing.md) — testing the integration layer
- [Multi-Document Architecture](18-multi-document-architecture.md) — partitioning and URL design
