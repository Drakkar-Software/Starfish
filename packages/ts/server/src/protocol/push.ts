import { computeHash } from "@drakkar.software/starfish-protocol"
import type { ObjectStore, StoreContext } from "../storage/base.js"
import type { PushResult, PushSuccess, PushConflict, StoredDocument, AppendElement } from "./types.js"
import { DOCUMENT_VERSION } from "./types.js"
import {
  ERROR_HASH_MISMATCH,
  CONTENT_TYPE_JSON,
  ERROR_APPEND_LIMIT_EXCEEDED,
  APPEND_SEG_SUFFIX,
  APPEND_SEG_TS_WIDTH,
  APPEND_DEFAULT_CHUNK_SIZE,
} from "../constants.js"

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

/** Returned by {@link appendItem} when the collection's `maxItems` cap is reached. */
export interface AppendLimitExceeded {
  error: "append_limit_exceeded"
  limit: number
}

export type AppendOutcome = PushSuccess | AppendConflict | AppendLimitExceeded

/** Opt-in append behaviours resolved from the collection's `appendOnly` config. */
export interface AppendOptions {
  /** Reject once the stored element count reaches this many ({@link AppendLimitExceeded}). */
  maxItems?: number
  /** Store the log as fixed-size sealed chunks of this many elements (segmented layout). */
  chunkSize?: number
}

/** Prefix under which a document's segmented-storage chunks live (a sibling of the
 *  head key, so the head stays a single object even on the filesystem backend). */
export function appendSegPrefix(documentKey: string): string {
  return documentKey + APPEND_SEG_SUFFIX
}

/** Key of the chunk whose first element has timestamp `firstTs`. The `firstTs` is
 *  zero-padded so the lexicographically sorted key list is chronological — a pull
 *  reads the sorted keys once (no chunk contents) to learn every chunk's ts range
 *  and skip chunks a `?checkpoint=` cannot match. */
export function appendChunkKey(documentKey: string, firstTs: number): string {
  // A negative `firstTs` (only reachable by migrating an unsupported ts-less
  // legacy element, where `elementTs` returns -1) must never form a key: JS
  // `padStart` keeps the sign mid-string (`00000000000000-1`) while Python
  // `zfill` puts it first (`-000000000000001`), so the two languages would
  // diverge AND the sign would break the lexicographic ordering the bisect
  // relies on. Fail closed so any reachable input is byte-identical cross-language.
  if (!Number.isInteger(firstTs) || firstTs < 0) {
    throw new Error(`appendChunkKey: firstTs must be a non-negative integer, got ${firstTs}`)
  }
  return appendSegPrefix(documentKey) + String(firstTs).padStart(APPEND_SEG_TS_WIDTH, "0")
}

/**
 * Append one element to an appendOnly (`by_timestamp`) collection.
 *
 * Runs the read → ts-resolve → append → write sequence inside the per-key
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
 * `opts.maxItems` (if set) rejects the append once the stored count reaches it.
 * `opts.chunkSize` (if set) selects the **segmented** layout — the log is stored as
 * fixed-size sealed chunks plus a small head, so an append touches only the head and
 * the open tail chunk (O(chunkSize), not O(n)); a legacy single-doc is lazily migrated
 * into chunks on its next append. Either way the wire output is identical: the stored
 * `hash` is `hash({ n, last })` where `last` is `item` only (not the `{ts, data}` envelope),
 * and `item` is stored opaquely (plaintext under `"none"`, an encryptor wrapper under
 * `"delegated"`).
 */
export function appendItem(
  store: ObjectStore,
  documentKey: string,
  item: unknown,
  appendField: string,
  providedTs: number | undefined,
  opts?: AppendOptions,
  context?: StoreContext,
): Promise<AppendOutcome> {
  const capturedContext = context
  return chain<AppendOutcome>(documentKey, () =>
    _appendImpl(store, documentKey, item, appendField, providedTs, opts ?? {}, capturedContext),
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
  opts: AppendOptions,
  context: StoreContext | undefined,
): Promise<AppendOutcome> {
  const raw = await store.getString(documentKey, context)

  let head: Record<string, unknown> | null = null
  if (raw) {
    try {
      head = JSON.parse(raw) as Record<string, unknown>
    } catch (e) {
      console.error(`[Starfish] Corrupt stored document at key "${documentKey}":`, e)
      head = null
    }
  }

  const isSeg = head != null && head["seg"] === true
  const existingData = (head?.["data"] as Record<string, unknown> | undefined) ?? {}
  const existingArr = Array.isArray(existingData[appendField]) ? (existingData[appendField] as unknown[]) : []
  const currentCount = isSeg ? ((head?.["n"] as number | undefined) ?? 0) : existingArr.length

  // Once a document is segmented it stays segmented, even if `chunkSize` was later
  // removed from config — otherwise this append would write a fresh single-doc at
  // the head key and orphan every existing chunk (silent data loss). Pull keys off
  // the stored `seg` flag the same way.
  const effectiveChunkSize = opts.chunkSize ?? (isSeg ? (((head?.["chunkSize"] as number | undefined) || APPEND_DEFAULT_CHUNK_SIZE)) : undefined)

  // Cap check first — never write past the configured limit.
  if (opts.maxItems != null && currentCount >= opts.maxItems) {
    return { error: ERROR_APPEND_LIMIT_EXCEEDED, limit: opts.maxItems } as AppendLimitExceeded
  }

  if (effectiveChunkSize != null) {
    return _appendChunkedImpl(store, documentKey, item, appendField, providedTs, effectiveChunkSize, head, isSeg, context)
  }

  // ---- single-document layout (legacy default; unchanged behaviour) ----
  const arr = existingArr
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

/**
 * Segmented append (selected by `chunkSize`). Touches only the head and the open
 * tail chunk, so cost is O(chunkSize) regardless of total log size. `head`/`isSeg`
 * are the already-read head (avoids a second read). A legacy single-doc (inline
 * `data[field]` array, no `seg`) is sliced into chunks on first append (one-time
 * O(n)); thereafter appends are bounded.
 */
async function _appendChunkedImpl(
  store: ObjectStore,
  documentKey: string,
  item: unknown,
  appendField: string,
  providedTs: number | undefined,
  chunkSize: number,
  head: Record<string, unknown> | null,
  isSeg: boolean,
  context: StoreContext | undefined,
): Promise<AppendOutcome> {
  let existingData: Record<string, unknown> = {}
  // `sealedN` = number of elements in all SEALED chunks (everything except the
  // open tail chunk). The total count is ALWAYS re-derived as
  // `sealedN + tailArr.length`, never read back as a standalone `n` — so a head
  // written one append behind (a crash between the chunk write and the head
  // write) self-corrects on the next append for the common, non-roll case:
  // `sealedN` is unchanged by a tail append, and `tailArr` is read authoritatively.
  let sealedN = 0
  let tailKey: string | null = null
  let tailArr: unknown[] = []
  let latest = -1

  if (isSeg && head) {
    existingData = (head["data"] as Record<string, unknown> | undefined) ?? {}
    tailKey = (head["tailKey"] as string | undefined) ?? null
    if (tailKey) {
      const tailRaw = await store.getString(tailKey, context)
      if (tailRaw) {
        try {
          tailArr = JSON.parse(tailRaw) as unknown[]
        } catch {
          tailArr = []
        }
      }
    }
    // Prefer the stored `sealedN`; fall back to `n - tailLen` for a pre-`sealedN`
    // head (a segmented doc written before this field existed) so the count is
    // preserved across the upgrade, then stays consistent from the next append on.
    const storedSealedN = head["sealedN"] as number | undefined
    sealedN =
      storedSealedN ??
      Math.max(0, ((head["n"] as number | undefined) ?? tailArr.length) - tailArr.length)
    // Authoritative `latest` from the tail's last element (robust to a stale head).
    latest = tailArr.length > 0 ? elementTs(tailArr[tailArr.length - 1]) : ((head["ts"] as number | undefined) ?? -1)
  } else if (head && Array.isArray((head["data"] as Record<string, unknown> | undefined)?.[appendField])) {
    // Lazy-migrate a legacy single-doc into sealed chunks.
    const legacyData = head["data"] as Record<string, unknown>
    const legacyArr = legacyData[appendField] as unknown[]
    existingData = { ...legacyData }
    delete existingData[appendField]
    const numFull = Math.floor(legacyArr.length / chunkSize)
    for (let c = 0; c < numFull; c++) {
      const chunk = legacyArr.slice(c * chunkSize, (c + 1) * chunkSize)
      await store.put(appendChunkKey(documentKey, elementTs(chunk[0])), JSON.stringify(chunk), { contentType: CONTENT_TYPE_JSON }, context)
    }
    tailArr = legacyArr.slice(numFull * chunkSize) // remainder (< chunkSize); written below with the new element
    tailKey = tailArr.length > 0 ? appendChunkKey(documentKey, elementTs(tailArr[0])) : null
    sealedN = numFull * chunkSize // the full chunks just written are sealed; the remainder is the open tail
    latest = legacyArr.length > 0 ? elementTs(legacyArr[legacyArr.length - 1]) : -1
  } else {
    // Fresh document (or a non-append doc at this key) — preserve any non-array data.
    existingData = (head?.["data"] as Record<string, unknown> | undefined) ?? {}
  }

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
  let writeKey: string
  let writeArr: unknown[]
  let newSealedN: number
  if (!tailKey || tailArr.length >= chunkSize) {
    // No open tail, or it is full → the current tail (if any) becomes sealed and
    // a new chunk opens, keyed by this element's ts.
    newSealedN = sealedN + tailArr.length
    writeKey = appendChunkKey(documentKey, ts)
    writeArr = [element]
  } else {
    // Append to the open tail; the sealed count is unchanged.
    newSealedN = sealedN
    writeKey = tailKey
    writeArr = [...tailArr, element]
  }

  // Count re-derived from authoritative state (sealed chunks + the tail being
  // written), never `previousN + 1` — so it cannot drift across a crash.
  const newN = newSealedN + writeArr.length
  const newHash = await computeHash({ n: newN, last: item })

  // Write the chunk first, then the head: a crash in between leaves the head one
  // element behind, but never loses a written element, and the persisted
  // `sealedN` lets the next append recompute the true count (non-roll case).
  await store.put(writeKey, JSON.stringify(writeArr), { contentType: CONTENT_TYPE_JSON }, context)
  const headDoc: Record<string, unknown> = {
    v: DOCUMENT_VERSION,
    seg: true,
    data: existingData,
    n: newN,
    sealedN: newSealedN,
    ts,
    hash: newHash,
    chunkSize,
    tailKey: writeKey,
  }
  await store.put(documentKey, JSON.stringify(headDoc), { contentType: CONTENT_TYPE_JSON }, context)

  return { hash: newHash, timestamp: ts } as PushSuccess
}
