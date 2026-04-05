import type { PullResult } from "@starfish/protocol"
import type { AbstractObjectStore } from "../storage/base.js"
import type { StoredDocument } from "./types.js"
import { filterByCheckpoint } from "./timestamps.js"

export async function pull(
  store: AbstractObjectStore,
  documentKey: string,
  checkpoint = 0,
): Promise<PullResult> {
  const timestamp = Date.now()
  const raw = await store.getString(documentKey)
  if (!raw) {
    return { data: {}, hash: "", timestamp }
  }

  const doc: StoredDocument = JSON.parse(raw)

  let data: Record<string, unknown>
  if (checkpoint > 0 && doc.timestamps) {
    data = filterByCheckpoint(doc.data, doc.timestamps, checkpoint)
  } else {
    data = doc.data
  }

  const result: PullResult = {
    data,
    hash: doc.hash,
    timestamp,
  }

  if (doc.authorPubkey) result.authorPubkey = doc.authorPubkey
  if (doc.authorSignature) result.authorSignature = doc.authorSignature

  return result
}
