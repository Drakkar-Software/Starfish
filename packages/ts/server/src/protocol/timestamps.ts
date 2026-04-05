import { stableStringify } from "@starfish/protocol"
import type { Timestamps } from "./types.js"

function isLeaf(v: unknown): boolean {
  return v === null || v === undefined || typeof v !== "object" || Array.isArray(v)
}

function stableEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  return stableStringify(a) === stableStringify(b)
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

    if (isLeaf(newVal)) {
      if (stableEqual(oldVal, newVal) && oldTimestamps && typeof oldTimestamps[key] === "number") {
        result[key] = oldTimestamps[key]
      } else {
        result[key] = now
      }
    } else {
      const oldSub =
        oldVal !== null && oldVal !== undefined && typeof oldVal === "object" && !Array.isArray(oldVal)
          ? (oldVal as Record<string, unknown>)
          : null
      const oldTsSub =
        oldTimestamps &&
        oldTimestamps[key] !== null &&
        oldTimestamps[key] !== undefined &&
        typeof oldTimestamps[key] === "object" &&
        !Array.isArray(oldTimestamps[key])
          ? (oldTimestamps[key] as Timestamps)
          : null
      result[key] = computeTimestamps(oldSub, newVal as Record<string, unknown>, oldTsSub, now)
    }
  }

  return result
}

export function filterByCheckpoint(
  data: Record<string, unknown>,
  timestamps: Timestamps,
  checkpoint: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const key of Object.keys(data)) {
    const ts = timestamps[key]
    const val = data[key]

    if (typeof ts === "number") {
      if (ts > checkpoint) {
        result[key] = val
      }
    } else if (ts && typeof ts === "object" && !Array.isArray(ts)) {
      const sub = filterByCheckpoint(
        val as Record<string, unknown>,
        ts as Timestamps,
        checkpoint,
      )
      if (Object.keys(sub).length > 0) {
        result[key] = sub
      }
    }
  }

  return result
}
