import type { ConflictResolver } from "./types.js"

/**
 * Creates a conflict resolver that merges arrays by ID with per-item
 * timestamp comparison, and uses document-level timestamp for scalars.
 *
 * For arrays: builds a union of both sets keyed by `idKey`. When both
 * sides have the same item, the one with the newer `timestampKey` wins.
 * For scalars: the document with the newer `documentTimestampKey` wins.
 *
 * @example
 * ```ts
 * const merge = createUnionMerge()
 * const sync = new SyncManager({ ..., onConflict: merge })
 * ```
 */
export function createUnionMerge(options?: {
  /** Key used to identify items in arrays (default: "id"). */
  idKey?: string
  /** Key used for per-item timestamp comparison (default: "updatedAt"). */
  timestampKey?: string
  /** Key used for document-level timestamp comparison (default: "timestamp"). */
  documentTimestampKey?: string
}): ConflictResolver {
  const idKey = options?.idKey ?? "id"
  const tsKey = options?.timestampKey ?? "updatedAt"
  const docTsKey = options?.documentTimestampKey ?? "timestamp"

  return (local, remote) => {
    const result: Record<string, unknown> = {}
    const localNewer = String(local[docTsKey] ?? "") >= String(remote[docTsKey] ?? "")
    const allKeys = new Set([...Object.keys(local), ...Object.keys(remote)])

    for (const key of allKeys) {
      const lv = local[key]
      const rv = remote[key]

      // Both sides have arrays — attempt ID-based union
      if (Array.isArray(lv) && Array.isArray(rv)) {
        const map = new Map<unknown, Record<string, unknown>>()

        // Seed with remote items
        for (const item of rv) {
          if (item && typeof item === "object" && idKey in item) {
            map.set((item as Record<string, unknown>)[idKey], item as Record<string, unknown>)
          } else {
            map.set(Symbol(), item as Record<string, unknown>)
          }
        }

        // Overlay local items (per-item timestamp wins)
        for (const item of lv) {
          if (item && typeof item === "object" && idKey in item) {
            const localItem = item as Record<string, unknown>
            const id = localItem[idKey]
            const remoteItem = map.get(id)
            if (!remoteItem) {
              map.set(id, localItem)
            } else {
              const localTs = String(localItem[tsKey] ?? "")
              const remoteTs = String(remoteItem[tsKey] ?? "")
              if (localTs >= remoteTs) {
                map.set(id, localItem)
              }
            }
          } else {
            map.set(Symbol(), item as Record<string, unknown>)
          }
        }

        result[key] = [...map.values()]
      } else if (lv !== undefined && rv !== undefined) {
        // Scalar: document-level timestamp wins
        result[key] = localNewer ? lv : rv
      } else {
        // Only one side has the key
        result[key] = lv ?? rv
      }
    }

    return result
  }
}

/**
 * Creates a conflict resolver that handles soft-deleted items (tombstones).
 * Extends union merge: items with a `deletedAtKey` are preserved as tombstones
 * so deletions propagate across devices.
 */
export function createSoftDeleteResolver(options?: {
  idKey?: string
  timestampKey?: string
  documentTimestampKey?: string
  /** Key marking an item as deleted (default: "_deletedAt"). */
  deletedAtKey?: string
}): ConflictResolver {
  const deletedAtKey = options?.deletedAtKey ?? "_deletedAt"
  const baseMerge = createUnionMerge(options)

  return (local, remote) => {
    const merged = baseMerge(local, remote)

    // Keep tombstones — don't let union merge "resurrect" deleted items
    // An item is a tombstone if it has the deletedAt key set
    for (const key of Object.keys(merged)) {
      const value = merged[key]
      if (!Array.isArray(value)) continue

      // No filtering needed — tombstones are preserved by the union merge
      // because they have IDs and timestamps like any other item.
      // The deletedAt field is just data that the app interprets.
    }

    return merged
  }
}

/**
 * Simple resolver: the document with the newer timestamp wins entirely.
 * No per-field or per-item merging.
 */
export function timestampWinner(
  timestampKey = "timestamp",
): ConflictResolver {
  return (local, remote) => {
    return String(local[timestampKey] ?? "") >= String(remote[timestampKey] ?? "")
      ? local
      : remote
  }
}

/**
 * Remove expired tombstones from an array of items.
 * Items with a `deletedAtKey` older than `ttlMs` are pruned.
 *
 * @param items - Array of items, some with a deletedAt timestamp
 * @param ttlMs - Time-to-live in ms for tombstones (default: 30 days)
 * @param deletedAtKey - Key marking deletion timestamp (default: "_deletedAt")
 */
export function pruneTombstones<T extends Record<string, unknown>>(
  items: T[],
  ttlMs = 30 * 24 * 60 * 60 * 1000,
  deletedAtKey = "_deletedAt",
): T[] {
  const cutoff = Date.now() - ttlMs
  return items.filter((item) => {
    const deletedAt = item[deletedAtKey]
    if (deletedAt == null) return true
    return typeof deletedAt === "number" && deletedAt > cutoff
  })
}
