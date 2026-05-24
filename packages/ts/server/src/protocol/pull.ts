import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { PullResult, StoredDocument } from "./types.js"

/**
 * Regular (non-appendOnly) pull. Always returns the full stored document —
 * `?checkpoint=` incremental filtering was removed for regular collections and
 * is now an appendOnly-only concept (see `handleAppendOnlyPull`). The returned
 * `timestamp` is the pull time, used by the client only as a high-water mark.
 */
export async function pull(
  store: ObjectStore,
  documentKey: string,
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

  return {
    data: parsed.data,
    hash: parsed.hash,
    timestamp,
    authorPubkey: parsed.authorPubkey,
    authorSignature: parsed.authorSignature,
  }
}
