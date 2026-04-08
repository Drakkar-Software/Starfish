# Conflict Resolution

Starfish uses optimistic concurrency control. When two clients push simultaneously, the server detects the conflict and the client resolves it automatically.

> **Prerequisites:** [SyncManager](03-sync-manager.md)

## How Conflicts Arise

Every push includes a `baseHash` — the hash of the last known server version. If the server's current hash doesn't match, it returns a 409 Conflict.

```
Device A pulls   (hash: "abc123")
Device B pulls   (hash: "abc123")
Device A pushes  (baseHash: "abc123") → 200 OK, new hash: "def456"
Device B pushes  (baseHash: "abc123") → 409 Conflict (server is now "def456")
```

## Default Strategy: `deepMerge`

When no custom resolver is provided, `SyncManager` uses `deepMerge`:

- **Scalars**: remote wins
- **Nested objects**: recursively merged
- **Arrays**: atomic — remote wins entirely (no element-level merge)

```ts
const sync = new SyncManager({
  client,
  pullPath, pushPath,
  // default: onConflict = deepMerge (remote wins)
})
```

## Automatic Retry

On conflict, `SyncManager` automatically:

1. Pulls the latest remote state
2. Calls `onConflict(localData, remoteData)` to produce a merged result
3. Waits with exponential backoff
4. Retries the push with the merged data

**Backoff formula:**

```
delay = min(100ms * 2^attempt, 2000ms) + random(0–100ms)
```

| Attempt | Base delay | With jitter |
|---------|-----------|-------------|
| 0 | 100ms | 100–200ms |
| 1 | 200ms | 200–300ms |
| 2 | 400ms | 400–500ms |
| 3 | 800ms | 800–900ms |
| 4 | 1600ms | 1600–1700ms |
| 5+ | 2000ms | 2000–2100ms |

If all retries fail, `SyncManager` throws a `ConflictError`.

## Custom Conflict Resolvers

### `ConflictResolver` type

```ts
type ConflictResolver = (
  local: Record<string, unknown>,
  remote: Record<string, unknown>
) => Record<string, unknown>
```

### Remote wins (simple spread)

```ts
onConflict: (local, remote) => ({ ...local, ...remote })
```

### Local wins

```ts
onConflict: (local, remote) => ({ ...remote, ...local })
```

### ID-based union for arrays

Merge arrays by item `id`, keeping items from both sides. Local versions win for shared IDs:

```ts
onConflict: (local, remote) => {
  const merged: Record<string, unknown> = { ...remote }

  for (const [key, localVal] of Object.entries(local)) {
    const remoteVal = remote[key]

    if (Array.isArray(localVal) && Array.isArray(remoteVal)) {
      // Build map from remote, overlay local
      const byId = new Map<string, unknown>()
      for (const item of remoteVal) {
        if (item && typeof item === "object" && "id" in item) {
          byId.set((item as { id: string }).id, item)
        }
      }
      for (const item of localVal) {
        if (item && typeof item === "object" && "id" in item) {
          byId.set((item as { id: string }).id, item)
        }
      }
      merged[key] = [...byId.values()]
    }
  }

  return merged
}
```

### Item-level merge with ID + updatedAt

The ID-based union above always picks the local version for shared items. A more precise strategy uses a per-item `updatedAt` timestamp so the **most recent edit wins** regardless of which device it came from:

```ts
interface SyncItem {
  id: string
  updatedAt: number  // Date.now() at last modification
  [key: string]: unknown
}

function mergeArraysByTimestamp(
  localArr: SyncItem[],
  remoteArr: SyncItem[],
): SyncItem[] {
  const byId = new Map<string, SyncItem>()

  // Seed with remote items
  for (const item of remoteArr) {
    byId.set(item.id, item)
  }

  // Overlay local items — but only if they are newer
  for (const item of localArr) {
    const existing = byId.get(item.id)
    if (!existing || item.updatedAt > existing.updatedAt) {
      byId.set(item.id, item)
    }
  }

  return [...byId.values()]
}
```

Wire it into a full resolver:

```ts
onConflict: (local, remote) => {
  const merged: Record<string, unknown> = { ...remote }

  for (const [key, localVal] of Object.entries(local)) {
    const remoteVal = remote[key]
    if (Array.isArray(localVal) && Array.isArray(remoteVal)) {
      merged[key] = mergeArraysByTimestamp(
        localVal as SyncItem[],
        remoteVal as SyncItem[],
      )
    }
  }

  // For top-level scalars, pick from the document with the latest timestamp
  const localTs = (local._updatedAt as number) ?? 0
  const remoteTs = (remote._updatedAt as number) ?? 0
  if (localTs > remoteTs) {
    for (const [key, val] of Object.entries(local)) {
      if (!Array.isArray(val)) merged[key] = val
    }
  }

  return merged
}
```

This requires your domain stores to set `updatedAt: Date.now()` on every item mutation. See [Integration Patterns — Soft Delete](09-integration-patterns.md#soft-delete--tombstone-pattern) for how this interacts with deletions.

### Soft-delete-aware merge

When using [soft deletes](09-integration-patterns.md#soft-delete--tombstone-pattern), the merge must respect tombstones. Without this, a union merge "resurrects" items that one device deleted while another still had them:

```ts
function mergeWithSoftDelete(
  localArr: SyncItem[],
  remoteArr: SyncItem[],
): SyncItem[] {
  const byId = new Map<string, SyncItem>()

  for (const item of remoteArr) byId.set(item.id, item)
  for (const item of localArr) {
    const existing = byId.get(item.id)
    if (!existing || item.updatedAt > existing.updatedAt) {
      byId.set(item.id, item)
    }
  }

  return [...byId.values()]
  // Items with _deletedAt are kept in the array (tombstones preserved).
  // Your UI filters them out; see Integration Patterns for the full pattern.
}
```

The key insight: deleted items are **not removed** from the array — they carry a `_deletedAt` timestamp. The merge compares `updatedAt` as usual, so the most recent action (edit or delete) wins per item. See [Soft Delete](09-integration-patterns.md#soft-delete--tombstone-pattern) for the complete pattern.

### Timestamp-based (document-level)

Pick the newer document for top-level scalars:

```ts
onConflict: (local, remote) => {
  const localTs = (local._updatedAt as number) ?? 0
  const remoteTs = (remote._updatedAt as number) ?? 0
  return localTs > remoteTs ? local : remote
}
```

### Union for sets

Merge array values as sets (deduplication):

```ts
onConflict: (local, remote) => {
  const merged: Record<string, unknown> = { ...remote }
  for (const [key, localVal] of Object.entries(local)) {
    const remoteVal = remote[key]
    if (Array.isArray(localVal) && Array.isArray(remoteVal)) {
      merged[key] = [...new Set([...localVal, ...remoteVal])]
    }
  }
  return merged
}
```

## Handling Unresolvable Conflicts

```ts
import { ConflictError } from "@drakkar.software/starfish-client"

try {
  await sync.push(data)
} catch (err) {
  if (err instanceof ConflictError) {
    // All retries exhausted — surface to user or queue for later
    console.error("Sync conflict could not be resolved")
  }
}
```

## Tuning Retries

```ts
const sync = new SyncManager({
  client,
  pullPath, pushPath,
  maxRetries: 5,  // default is 3
  onConflict: myResolver,
})
```

Set `maxRetries: 0` to disable automatic retry — the first conflict will throw immediately.

## Choosing a Strategy

| Strategy | Best for | Limitation |
|----------|----------|------------|
| `deepMerge` (default) | Simple key-value documents | Arrays are atomic |
| Remote/local wins | Single-writer scenarios | Discards one side entirely |
| ID-based union | Multi-device item creation | Doesn't resolve same-item edits |
| ID + `updatedAt` | Per-item conflict resolution | Requires timestamp discipline |
| Soft-delete-aware | Apps with item deletion | Tombstones grow the document |
| Union for sets | Tag lists, labels | No ordering guarantees |

For most apps with array-heavy documents, **ID + `updatedAt` with soft-delete awareness** provides the best balance of correctness and simplicity.

## Conflict Metadata

Since v1.5.0, wrap any resolver with `withConflictMeta()` to get information about which fields conflicted and how the conflict was resolved:

```ts
import { createUnionMerge, withConflictMeta } from "@drakkar.software/starfish-client"

const merge = withConflictMeta(createUnionMerge())

const result = merge(
  { items: [{ id: 1, name: "A", updatedAt: 100 }], timestamp: 100 },
  { items: [{ id: 1, name: "B", updatedAt: 200 }], timestamp: 200 },
)

console.log(result.meta)
// {
//   conflictedFields: ["items", "timestamp"],
//   resolvedBy: "merged",  // or "local" or "remote"
//   timestamp: 1712345678000
// }
```

This is useful for showing users what changed during a conflict resolution, or for analytics.

## Next Steps

- [Integration Patterns](09-integration-patterns.md) — soft delete, local history, and more
- [Offline & Connectivity](08-offline-connectivity.md) — how dirty tracking interacts with conflicts
