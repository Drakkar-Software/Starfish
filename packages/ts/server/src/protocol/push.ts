import { computeHash } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { PushResult, PushSuccess, PushConflict, StoredDocument, AppendElement } from "./types.js"
import { DOCUMENT_VERSION } from "./types.js"
import { ERROR_HASH_MISMATCH, CONTENT_TYPE_JSON } from "../constants.js"

// Per-key promise chain serialises concurrent writes to the same documentKey.
// Node.js is single-threaded but awaits yield between the getString read and the
// put write — two concurrent writes can both read the same state and both succeed.
// Chaining guarantees the next write only starts after the previous one completes.
// Both `push` (regular) and `appendItem` (appendOnly) share this chain so they
// serialise against each other on the same key.
const writeChain = new Map<string, Promise<unknown>>()

function chain<T>(documentKey: string, run: () => Promise<T>): Promise<T> {
  const prev = writeChain.get(documentKey) ?? Promise.resolve()
  // Run regardless of whether the previous link resolved or rejected.
  const current: Promise<T> = prev.then(run, run)
  writeChain.set(documentKey, current)
  void current.finally(() => {
    if (writeChain.get(documentKey) === current) writeChain.delete(documentKey)
  })
  return current
}

export interface Author {
  pubkey: string
  signature: string
}

/**
 * Regular (non-appendOnly) push. Stores the whole `newData` object, gated by a
 * `baseHash` optimistic-concurrency check. A single document-level write
 * timestamp (`ts`) is recorded — the per-field `timestamps` tree and
 * `?checkpoint=` filtering were removed; regular pulls always return the full
 * document.
 */
export function push(
  store: ObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author?: Author,
  _skipTimestamps: boolean = false,
  skipStorage: boolean = false,
  precomputedHash?: string,
  context?: StoreContext,
): Promise<PushResult> {
  // skip-storage calls are stateless — no TOCTOU risk, no serialisation needed.
  if (skipStorage) {
    return (async () => {
      const now = Date.now()
      const newHash = precomputedHash ?? (await computeHash(newData))
      return { hash: newHash, timestamp: now } as PushSuccess
    })()
  }

  const capturedContext = context
  return chain<PushResult>(documentKey, () =>
    _pushImpl(store, documentKey, newData, baseHash, author, precomputedHash, capturedContext),
  )
}

async function _pushImpl(
  store: ObjectStore,
  documentKey: string,
  newData: Record<string, unknown>,
  baseHash: string | null,
  author: Author | undefined,
  precomputedHash: string | undefined,
  context: StoreContext | undefined,
): Promise<PushResult> {
  const raw = await store.getString(documentKey, context)

  let currentHash = ""
  if (raw) {
    try {
      const existing = JSON.parse(raw) as StoredDocument
      currentHash = existing.hash
    } catch (e) {
      console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
      // Treat as empty — allow overwrite to recover from corruption
    }
  }

  // Hash check (optimistic concurrency)
  if (baseHash == null) {
    if (raw) {
      return { error: ERROR_HASH_MISMATCH } as PushConflict
    }
  } else if (baseHash !== currentHash) {
    return { error: ERROR_HASH_MISMATCH } as PushConflict
  }

  const now = Date.now()
  const newHash = precomputedHash ?? (await computeHash(newData))

  const doc: Record<string, unknown> = {
    v: DOCUMENT_VERSION,
    data: newData,
    ts: now,
    hash: newHash,
  }
  if (author) {
    doc["authorPubkey"] = author.pubkey
    doc["authorSignature"] = author.signature
  }

  await store.put(documentKey, JSON.stringify(doc), { contentType: CONTENT_TYPE_JSON }, context)

  return { hash: newHash, timestamp: now } as PushSuccess
}

/** Conflict returned by {@link appendItem} when a client-supplied `ts` is not
 *  strictly greater than the most recent element's `ts`. */
export interface AppendConflict {
  error: "non_monotonic_timestamp"
  latest: number
}

export type AppendOutcome = PushSuccess | AppendConflict

/**
 * Append one element to an appendOnly (`by_timestamp`) collection.
 *
 * Runs the read → ts-resolve → append → write triplet inside the per-key
 * {@link writeChain} so concurrent appends serialise and never lose an element —
 * this replaces the old `baseHash`/hash-mismatch check, which is no longer used
 * for appendOnly (an authorized append is always accepted, content-wise).
 *
 * Timestamp rules (let `latest` = `ts` of the last stored element, or `-1` if empty):
 *   - `providedTs` given → require `providedTs > latest` (else `non_monotonic_timestamp`);
 *     store the element verbatim with `providedTs`.
 *   - `providedTs` omitted → store with `max(now, latest + 1)`, which keeps the array
 *     strictly increasing in `ts` (so the pull-side checkpoint binary search stays valid)
 *     even after a client previously stored a future `ts`.
 *
 * `item` (the element payload) is stored opaquely — plaintext under `"none"`,
 * an encryptor wrapper under `"delegated"`. The stored document `hash` is
 * `hash({ n, last })` where `last` is `item` only (not the `{ts, data}` envelope).
 */
export function appendItem(
  store: ObjectStore,
  documentKey: string,
  item: unknown,
  appendField: string,
  providedTs: number | undefined,
  context?: StoreContext,
): Promise<AppendOutcome> {
  const capturedContext = context
  return chain<AppendOutcome>(documentKey, () =>
    _appendImpl(store, documentKey, item, appendField, providedTs, capturedContext),
  )
}

// Reads an element's `ts`. Pre-refactor / mixed arrays (raw items without a `ts`)
// yield -1; such legacy docs are not supported (the format change is breaking and
// requires a wipe), and would mis-order/mis-slice under checkpoint — see CHANGELOG.
function elementTs(el: unknown): number {
  if (el != null && typeof el === "object" && typeof (el as AppendElement).ts === "number") {
    return (el as AppendElement).ts
  }
  return -1
}

async function _appendImpl(
  store: ObjectStore,
  documentKey: string,
  item: unknown,
  appendField: string,
  providedTs: number | undefined,
  context: StoreContext | undefined,
): Promise<AppendOutcome> {
  const raw = await store.getString(documentKey, context)

  let existingData: Record<string, unknown> = {}
  if (raw) {
    try {
      const doc = JSON.parse(raw) as StoredDocument
      existingData = (doc.data as Record<string, unknown>) ?? {}
    } catch (e) {
      console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
      existingData = {}
    }
  }

  const existing = existingData[appendField]
  const arr = Array.isArray(existing) ? (existing as unknown[]) : []
  const latest = arr.length > 0 ? elementTs(arr[arr.length - 1]) : -1

  const now = Date.now()
  let ts: number
  if (providedTs !== undefined) {
    if (!(providedTs > latest)) {
      return { error: "non_monotonic_timestamp", latest } as AppendConflict
    }
    ts = providedTs
  } else {
    ts = Math.max(now, latest + 1)
  }

  const element: AppendElement = { ts, data: item }
  const newArr = [...arr, element]
  const newHash = await computeHash({ n: newArr.length, last: item })

  const doc: Record<string, unknown> = {
    v: DOCUMENT_VERSION,
    data: { ...existingData, [appendField]: newArr },
    ts,
    hash: newHash,
  }

  await store.put(documentKey, JSON.stringify(doc), { contentType: CONTENT_TYPE_JSON }, context)

  return { hash: newHash, timestamp: ts } as PushSuccess
}
