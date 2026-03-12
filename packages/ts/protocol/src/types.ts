/** Response from a pull request. */
export interface PullResult {
  data: Record<string, unknown>
  hash: string
  timestamp: number
  authorPubkey?: string
  authorSignature?: string
}

/** Response from a successful push. */
export interface PushSuccess {
  hash: string
  timestamp: number
}
