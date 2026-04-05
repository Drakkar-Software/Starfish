import type { PushSuccess } from "@starfish/protocol"

export const DOCUMENT_VERSION = 1

export interface StoredDocument {
  v: number
  data: Record<string, unknown>
  timestamps: Timestamps
  hash: string
  authorPubkey?: string
  authorSignature?: string
}

export type Timestamps = Record<string, unknown>

export interface PushConflict {
  error: string
}

export type PushResult = PushSuccess | PushConflict

export function isPushConflict(result: PushResult): result is PushConflict {
  return "error" in result
}
