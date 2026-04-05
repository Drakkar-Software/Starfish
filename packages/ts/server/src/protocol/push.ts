import { computeHash } from "@starfish/protocol"
import type { AbstractObjectStore } from "../storage/base.js"
import type { PushResult, StoredDocument } from "./types.js"
import { DOCUMENT_VERSION } from "./types.js"
import { computeTimestamps } from "./timestamps.js"
import { ERROR_HASH_MISMATCH } from "../constants.js"

export interface Author {
  pubkey: string
  signature: string
}

export async function push(
  store: AbstractObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author?: Author,
  skipTimestamps = false,
): Promise<PushResult> {
  const raw = await store.getString(documentKey)

  let oldData: Record<string, unknown> | null = null
  let oldTimestamps: Record<string, unknown> | null = null
  let currentHash = ""

  if (raw) {
    const doc: StoredDocument = JSON.parse(raw)
    oldData = doc.data
    oldTimestamps = doc.timestamps ?? null
    currentHash = doc.hash
  }

  if (baseHash !== null && baseHash !== currentHash) {
    return { error: ERROR_HASH_MISMATCH }
  }

  const newHash = await computeHash(newData)
  const now = Date.now()

  const timestamps = skipTimestamps
    ? {}
    : computeTimestamps(oldData, newData, oldTimestamps, now)

  const doc: StoredDocument = {
    v: DOCUMENT_VERSION,
    data: newData,
    timestamps,
    hash: newHash,
  }

  if (author) {
    doc.authorPubkey = author.pubkey
    doc.authorSignature = author.signature
  }

  await store.put(documentKey, JSON.stringify(doc))

  return { hash: newHash, timestamp: now }
}
