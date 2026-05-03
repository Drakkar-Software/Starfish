import { computeHash } from "@drakkar.software/starfish-protocol"
import type { ObjectStore } from "../storage/base.js"
import type { StoredDocument, Timestamps } from "./types.js"

export interface AppendTransformResult {
  data: Record<string, unknown>
  baseHash: string
  timestamps: Timestamps  // full timestamps to store (appendField → number[]; others preserved)
  lastItemHash: string    // computeHash({ n: items.length, last: newItem }) — O(1)
}

export async function buildAppendOnlyData(
  store: ObjectStore,
  documentKey: string,
  newItem: Record<string, unknown>,
  appendField: string,
  now: number,
): Promise<AppendTransformResult> {
  const raw = await store.getString(documentKey)

  if (!raw) {
    const lastItemHash = await computeHash({ n: 1, last: newItem })
    return {
      data: { [appendField]: [newItem] },
      baseHash: "",
      timestamps: { [appendField]: [now] },
      lastItemHash,
    }
  }

  let existingData: Record<string, unknown> = {}
  let baseHash = ""
  let existingTimestamps: Timestamps = {}

  try {
    const doc = JSON.parse(raw) as StoredDocument
    existingData = (doc.data as Record<string, unknown>) ?? {}
    baseHash = doc.hash ?? ""
    existingTimestamps = (doc.timestamps ?? {}) as Timestamps
  } catch (e) {
    console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
    const lastItemHash = await computeHash({ n: 1, last: newItem })
    return {
      data: { [appendField]: [newItem] },
      baseHash: "",
      timestamps: { [appendField]: [now] },
      lastItemHash,
    }
  }

  const existing = existingData[appendField]
  const arr = Array.isArray(existing) ? (existing as Record<string, unknown>[]) : []
  const newArr = [...arr, newItem]

  // Build per-item timestamps: preserve existing number[] or backfill with now for legacy docs
  const prevItemTs = existingTimestamps[appendField]
  const isValidTs = Array.isArray(prevItemTs) && prevItemTs.every((t) => typeof t === "number")
  if (isValidTs && (prevItemTs as number[]).length !== arr.length) {
    console.warn(`[Starfish] Timestamp/items length mismatch at key "${documentKey}" (${(prevItemTs as number[]).length} vs ${arr.length}); backfilling`)
  }
  const itemTs: number[] = isValidTs && (prevItemTs as number[]).length === arr.length
    ? (prevItemTs as number[])
    : arr.map(() => now)
  const newItemTs = [...itemTs, now]

  const lastItemHash = await computeHash({ n: newArr.length, last: newItem })

  return {
    data: { ...existingData, [appendField]: newArr },
    baseHash,
    timestamps: { ...existingTimestamps, [appendField]: newItemTs },
    lastItemHash,
  }
}

/**
 * Compares clientBaseHash against the stored document hash.
 * For appendOnly collections the stored hash is hash({ n, last }) — the
 * client should pass back the hash received from the last pull response.
 * Returns null (no conflict) or "hash_mismatch".
 *
 * Not called by the route-builder (the check runs inline inside the retry loop
 * using the baseHash already returned by buildAppendOnlyData). Exported as a
 * utility for callers that manage their own retry logic.
 */
export async function checkLastItemConflict(
  store: ObjectStore,
  documentKey: string,
  clientBaseHash: string | null | undefined,
  _appendField: string,
): Promise<string | null> {
  const raw = await store.getString(documentKey)

  if (!raw) {
    if (clientBaseHash && clientBaseHash !== "") return "hash_mismatch"
    return null
  }

  try {
    const doc = JSON.parse(raw) as StoredDocument
    const storedHash = doc.hash ?? ""
    if (clientBaseHash !== storedHash) return "hash_mismatch"
    return null
  } catch {
    return "hash_mismatch"
  }
}
