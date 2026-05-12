import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { PullResult, StoredDocument } from "./types.js"
import { filterByCheckpoint } from "./timestamps.js"

export async function pull(
  store: ObjectStore,
  documentKey: string,
  checkpoint: number = 0,
  context?: StoreContext,
): Promise<PullResult> {
  const timestamp = Date.now()
  const raw = await store.getString(documentKey, context)

  if (!raw) {
    return { data: {}, hash: "", timestamp }
  }

  let parsed: StoredDocument
  try {
    parsed = JSON.parse(raw) as StoredDocument
  } catch (e) {
    console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
    return { data: {}, hash: "", timestamp }
  }

  if (checkpoint && checkpoint > 0 && parsed.timestamps && Object.keys(parsed.timestamps).length > 0) {
    const filtered = filterByCheckpoint(parsed.data, parsed.timestamps, checkpoint)
    return {
      data: filtered,
      hash: parsed.hash,
      timestamp,
      authorPubkey: parsed.authorPubkey,
      authorSignature: parsed.authorSignature,
    }
  }

  return {
    data: parsed.data,
    hash: parsed.hash,
    timestamp,
    authorPubkey: parsed.authorPubkey,
    authorSignature: parsed.authorSignature,
  }
}
