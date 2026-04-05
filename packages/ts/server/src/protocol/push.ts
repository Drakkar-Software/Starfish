import { computeHash } from "@drakkarsoftware/starfish-protocol"
import type { ObjectStore } from "../storage/base.js"
import type { PushResult, PushSuccess, PushConflict, StoredDocument, Timestamps } from "./types.js"
import { DOCUMENT_VERSION } from "./types.js"
import { computeTimestamps } from "./timestamps.js"
import { ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON } from "../constants.js"

export interface Author {
  pubkey: string
  signature: string
}

export async function push(
  store: ObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author?: Author,
  skipTimestamps: boolean = false,
): Promise<PushResult> {
  const raw = await store.getString(documentKey)

  let oldData: Record<string, unknown> | null = null
  let oldTimestamps: Timestamps | null = null
  let currentHash = ""

  if (raw) {
    try {
      const existing = JSON.parse(raw) as StoredDocument
      oldData = existing.data
      oldTimestamps = existing.timestamps
      currentHash = existing.hash
    } catch (e) {
      console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
      // Treat as empty — allow overwrite to recover from corruption
    }
  }

  // Hash check
  if (baseHash == null) {
    if (raw) {
      return { error: ERROR_HASH_MISMATCH } as PushConflict
    }
  } else {
    if (baseHash !== currentHash) {
      return { error: ERROR_HASH_MISMATCH } as PushConflict
    }
  }

  const now = Date.now()
  const newHash = await computeHash(newData)
  const timestamps = skipTimestamps
    ? {}
    : computeTimestamps(oldData, newData, oldTimestamps, now)

  const doc: Record<string, unknown> = {
    v: DOCUMENT_VERSION,
    data: newData,
    timestamps,
    hash: newHash,
  }
  if (author) {
    doc["authorPubkey"] = author.pubkey
    doc["authorSignature"] = author.signature
  }

  await store.put(documentKey, JSON.stringify(doc), { contentType: CONTENT_TYPE_JSON })

  return { hash: newHash, timestamp: now } as PushSuccess
}
