import { computeHash } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { PushResult, PushSuccess, PushConflict, StoredDocument, Timestamps } from "./types.js"
import { DOCUMENT_VERSION } from "./types.js"
import { computeTimestamps } from "./timestamps.js"
import { ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON } from "../constants.js"

// Per-key promise chain serialises concurrent pushes to the same documentKey.
// Node.js is single-threaded but awaits yield between the getString read and the
// put write — two concurrent pushes can both read the same hash and both succeed.
// Chaining guarantees the second push only starts after the first write completes.
const pushChain = new Map<string, Promise<PushResult>>()

export interface Author {
  pubkey: string
  signature: string
}

export function push(
  store: ObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author?: Author,
  skipTimestamps: boolean = false,
  skipStorage: boolean = false,
  precomputedHash?: string,
  precomputedTimestamps?: Timestamps,
  context?: StoreContext,
): Promise<PushResult> {
  // skip-storage calls are stateless — no TOCTOU risk, no serialisation needed.
  if (skipStorage) {
    return (async () => {
      const now = Date.now()
      const newHash = precomputedHash ?? await computeHash(newData)
      return { hash: newHash, timestamp: now } as PushSuccess
    })()
  }

  // Chain onto any in-flight push for the same key so the read-check-write
  // triplet is never interleaved with a concurrent push for the same document.
  // Capture context per-call in the closure so concurrent pushes carry their own ctx.
  const capturedContext = context
  const prev = pushChain.get(documentKey) ?? Promise.resolve<PushResult>({} as PushResult)
  const current: Promise<PushResult> = prev.then(
    () => _pushImpl(store, documentKey, newData, baseHash, author, skipTimestamps, precomputedHash, precomputedTimestamps, capturedContext),
    () => _pushImpl(store, documentKey, newData, baseHash, author, skipTimestamps, precomputedHash, precomputedTimestamps, capturedContext),
  )
  pushChain.set(documentKey, current)
  // Clean up map entry once this push is the last one in the chain
  void current.finally(() => {
    if (pushChain.get(documentKey) === current) pushChain.delete(documentKey)
  })
  return current
}

async function _pushImpl(
  store: ObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author: Author | undefined,
  skipTimestamps: boolean,
  precomputedHash: string | undefined,
  precomputedTimestamps: Timestamps | undefined,
  context: StoreContext | undefined,
): Promise<PushResult> {
  const raw = await store.getString(documentKey, context)

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
  const newHash = precomputedHash ?? await computeHash(newData)
  const timestamps = skipTimestamps
    ? {}
    : (precomputedTimestamps ?? computeTimestamps(oldData, newData, oldTimestamps, now))

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

  await store.put(documentKey, JSON.stringify(doc), { contentType: CONTENT_TYPE_JSON }, context)

  return { hash: newHash, timestamp: now } as PushSuccess
}
