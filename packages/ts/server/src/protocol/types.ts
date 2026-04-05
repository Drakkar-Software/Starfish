import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"

export type { PullResult, PushSuccess }

export interface Timestamps {
  [key: string]: number | Timestamps
}

export const DOCUMENT_VERSION = 1

export interface StoredDocument {
  v: number
  data: Record<string, unknown>
  timestamps: Timestamps
  hash: string
  authorPubkey?: string
  authorSignature?: string
}

export interface PushConflict {
  error: "hash_mismatch"
}

export type PushResult = PushSuccess | PushConflict
