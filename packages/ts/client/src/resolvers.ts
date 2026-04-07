import type { ConflictResolver } from "./types.js"

/** Compare two timestamp values. Handles both numeric (epoch) and string (ISO-8601) timestamps. */
function compareTimestamps(a: unknown, b: unknown): boolean {
  if (typeof a === "number" && typeof b === "number") return a >= b
  return String(a ?? "") >= String(b ?? "")
}

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
    const localNewer = compareTimestamps(local[docTsKey], remote[docTsKey])
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
              if (compareTimestamps(localItem[tsKey], remoteItem[tsKey])) {
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
 * Extends union merge with tombstone awareness: if an item exists on one side
 * with a `deletedAtKey` set, that deletion is respected even if the other side
 * still has the item alive — as long as the deletion timestamp is newer.
 */
export function createSoftDeleteResolver(options?: {
  idKey?: string
  timestampKey?: string
  documentTimestampKey?: string
  /** Key marking an item as deleted (default: "_deletedAt"). */
  deletedAtKey?: string
}): ConflictResolver {
  const idKey = options?.idKey ?? "id"
  const tsKey = options?.timestampKey ?? "updatedAt"
  const deletedAtKey = options?.deletedAtKey ?? "_deletedAt"
  const baseMerge = createUnionMerge(options)

  return (local, remote) => {
    const merged = baseMerge(local, remote)

    // Build a tombstone map from both sides: id → deletedAt timestamp
    const tombstones = new Map<unknown, unknown>()
    for (const source of [local, remote]) {
      for (const key of Object.keys(source)) {
        const arr = source[key]
        if (!Array.isArray(arr)) continue
        for (const item of arr) {
          if (item && typeof item === "object" && idKey in item && deletedAtKey in item) {
            const rec = item as Record<string, unknown>
            const id = rec[idKey]
            const deletedAt = rec[deletedAtKey]
            if (typeof deletedAt === "number" || typeof deletedAt === "string") {
              const existing = tombstones.get(id)
              if (existing == null || compareTimestamps(deletedAt, existing)) tombstones.set(id, deletedAt)
            }
          }
        }
      }
    }

    // For merged arrays, ensure tombstoned items stay deleted
    // (don't resurrect an item if its tombstone is newer than its updatedAt)
    for (const key of Object.keys(merged)) {
      const value = merged[key]
      if (!Array.isArray(value)) continue

      merged[key] = value.filter((item) => {
        if (!item || typeof item !== "object" || !(idKey in item)) return true
        const rec = item as Record<string, unknown>
        const id = rec[idKey]
        const deletedAt = tombstones.get(id)
        if (deletedAt == null) return true
        // Keep the item if it has a deletedAt (it's the tombstone itself)
        if (rec[deletedAtKey] != null) return true
        // Filter out alive items that have a newer tombstone
        return compareTimestamps(rec[tsKey], deletedAt) && rec[tsKey] !== deletedAt
      })
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
    return compareTimestamps(local[timestampKey], remote[timestampKey])
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
    if (typeof deletedAt === "number") return deletedAt > cutoff
    if (typeof deletedAt === "string") return new Date(deletedAt).getTime() > cutoff
    return false
  })
}
