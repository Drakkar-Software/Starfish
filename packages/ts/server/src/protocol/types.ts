import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"

export type { PullResult, PushSuccess }

export const DOCUMENT_VERSION = 1

/** One element of an appendOnly (`by_timestamp`) collection's stored array.
 *  `ts` (the server-visible plaintext timestamp) drives `?checkpoint=` filtering;
 *  `data` is opaque — plaintext under `"none"`, an encryptor wrapper under `"delegated"`. */
export interface AppendElement {
  ts: number
  data: unknown
}

export interface StoredDocument {
  v: number
  data: Record<string, unknown>
  /** Document write-time (ms). Used for TTL and as the high-water mark on pull.
   *  For a regular doc it is the time of the last write; for an appendOnly doc
   *  it equals the `ts` of the most recent element. This is the only timestamp a
   *  document carries — the old per-field `timestamps` tree was removed. */
  ts?: number
  hash: string
  authorPubkey?: string
  authorSignature?: string
}

export interface PushConflict {
  error: "hash_mismatch"
}

export type PushResult = PushSuccess | PushConflict
