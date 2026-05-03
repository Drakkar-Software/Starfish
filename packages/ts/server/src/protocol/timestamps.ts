import type { Timestamps } from "./types.js"

function isLeaf(v: unknown): boolean {
  if (v == null) return true
  if (Array.isArray(v)) return true
  return typeof v !== "object"
}

function stableEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (a == null || b == null) return a === b
  if (typeof a !== typeof b) return false
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false
    return a.every((x, i) => stableEqual(x, b[i]))
  }
  return a === b
}

export function computeTimestamps(
  oldData: Record<string, unknown> | null,
  newData: Record<string, unknown>,
  oldTimestamps: Timestamps | null,
  now: number,
): Timestamps {
  const result: Timestamps = {}

  for (const key of Object.keys(newData)) {
    const newVal = newData[key]
    const oldVal = oldData ? oldData[key] : undefined
    const oldTs = oldTimestamps ? oldTimestamps[key] : undefined

    if (isLeaf(newVal)) {
      if (
        oldData != null &&
        key in oldData &&
        isLeaf(oldVal) &&
        stableEqual(oldVal, newVal) &&
        typeof oldTs === "number"
      ) {
        result[key] = oldTs
      } else {
        result[key] = now
      }
    } else {
      // Object: recurse
      const newObj = newVal as Record<string, unknown>
      const oldObj =
        oldVal != null && !isLeaf(oldVal) ? (oldVal as Record<string, unknown>) : null
      const oldTsObj =
        oldTs != null && typeof oldTs === "object" ? (oldTs as Timestamps) : null
      result[key] = computeTimestamps(oldObj, newObj, oldTsObj, now)
    }
  }

  return result
}

/**
 * Recursively find the maximum leaf timestamp in a timestamps tree.
 * Returns 0 if the tree is empty or contains no numeric leaves.
 */
export function maxLeafTimestamp(timestamps: Timestamps | unknown): number {
  if (typeof timestamps === "number") return timestamps
  if (Array.isArray(timestamps)) {
    let max = 0
    for (const v of timestamps) {
      if (typeof v === "number" && v > max) max = v
    }
    return max
  }
  if (timestamps != null && typeof timestamps === "object") {
    let max = 0
    for (const v of Object.values(timestamps as Record<string, unknown>)) {
      const t = maxLeafTimestamp(v)
      if (t > max) max = t
    }
    return max
  }
  return 0
}

export function filterByCheckpoint(
  data: Record<string, unknown>,
  timestamps: Timestamps,
  checkpoint: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const key of Object.keys(data)) {
    const val = data[key]
    const ts = timestamps[key]

    if (ts == null) continue

    if (typeof ts === "number") {
      if (ts > checkpoint) {
        result[key] = val
      }
    } else if (!Array.isArray(ts)) {
      // Nested object timestamps (number[] is appendOnly per-item — not recursed into here)
      if (isLeaf(val)) {
        result[key] = val
      } else {
        const filtered = filterByCheckpoint(val as Record<string, unknown>, ts, checkpoint)
        if (Object.keys(filtered).length > 0) {
          result[key] = filtered
        }
      }
    }
  }

  return result
}
