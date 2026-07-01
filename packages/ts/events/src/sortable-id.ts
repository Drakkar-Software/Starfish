/**
 * Server-assigned, lexicographically-sortable batch id.
 *
 * The events plugin uses this instead of trusting the client-supplied
 * `{batchId}` URL param, so that Starfish's `/list` route — which returns
 * keys in ascending lexicographic order — doubles as a chronological cursor.
 * A client-minted id can't provide that guarantee: batches are pushed from
 * many end-user devices with untrusted, possibly-skewed clocks, so a
 * lexicographic cursor over client timestamps could permanently miss a batch
 * from a clock-skewed-slow device. Stamping the id from the single server
 * clock at ingest time avoids that.
 *
 * Format: `<13-digit zero-padded epoch-ms>-<4-digit per-ms counter>-<6-hex random>`
 * e.g. `0001700000000123-0007-a1b2c3`.
 *
 * - The epoch-ms segment is fixed-width, so string order matches time order.
 * - The counter breaks ties for ids minted within the same millisecond by
 *   this process (wraps at 10000 — astronomically unlikely for a Parquet
 *   encode + object-store write per request, and a same-value wrap only
 *   risks a duplicate rank within that millisecond, not an incorrect one).
 * - The random suffix guarantees the storage key is unique even on a
 *   counter wrap or a clock that runs backwards.
 *
 * Ordering is guaranteed only *within one server process*. Multiple sync-
 * server instances each mint their own monotonic sequence, so cross-instance
 * ordering isn't guaranteed — callers that need a resumable cursor across a
 * multi-instance deployment must still dedupe against already-seen ids (as
 * the SunGlasses dashboard's manifest already does).
 */
import { getCrypto, bytesToHex } from "@drakkar.software/starfish-protocol"

let lastMs = 0
let counter = 0

/** Generate the next sortable id. `nowMs` is injectable for tests. */
export function generateSortableBatchId(nowMs: number = Date.now()): string {
  if (nowMs === lastMs) {
    counter = (counter + 1) % 10000
  } else {
    lastMs = nowMs
    counter = 0
  }

  const msPart = String(nowMs).padStart(13, "0")
  const counterPart = String(counter).padStart(4, "0")

  const randomBytes = new Uint8Array(3)
  getCrypto().getRandomValues(randomBytes)
  const randomPart = bytesToHex(randomBytes)

  return `${msPart}-${counterPart}-${randomPart}`
}
