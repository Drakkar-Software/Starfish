import type { PullResult } from "@starfish/protocol"
import type { AbstractObjectStore } from "../storage/base.js"
import type { StoredDocument } from "./types.js"
import { filterByCheckpoint } from "./timestamps.js"

export async function pull(
  store: AbstractObjectStore,
  documentKey: string,
  checkpoint = 0,
): Promise<PullResult> {
  const raw = await store.getString(documentKey)
  if (!raw) {
    return { data: {}, hash: "", timestamp: 0 }
  }

  const doc: StoredDocument = JSON.parse(raw)
  const fullData = doc.data
  const fullHash = doc.hash

  let data: Record<string, unknown>
  if (checkpoint > 0 && doc.timestamps) {
    data = filterByCheckpoint(fullData, doc.timestamps, checkpoint)
  } else {
    data = fullData
  }

  const result: PullResult = {
    data,
    hash: fullHash,
    timestamp: Math.max(checkpoint, maxTimestamp(doc.timestamps)),
  }

  if (doc.authorPubkey) result.authorPubkey = doc.authorPubkey
  if (doc.authorSignature) result.authorSignature = doc.authorSignature

  return result
}

function maxTimestamp(timestamps: Record<string, unknown>): number {
  let max = 0
  for (const val of Object.values(timestamps ?? {})) {
    if (typeof val === "number") {
      if (val > max) max = val
    } else if (val && typeof val === "object" && !Array.isArray(val)) {
      const sub = maxTimestamp(val as Record<string, unknown>)
      if (sub > max) max = sub
    }
  }
  return max
}
