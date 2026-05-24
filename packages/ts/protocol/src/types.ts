/**
 * Per-field last-modified timestamps for a document. Numeric leaves are
 * scalar field timestamps; arrays of numbers are append-only field
 * timestamps (one entry per item); nested objects mirror nested fields.
 *
 * Mirror of the Python protocol's `Timestamps` type alias. Server-side
 * code is the primary consumer (see `@drakkar.software/starfish-server`);
 * exporting it from the protocol package gives cross-language parity.
 */
export interface Timestamps {
  [key: string]: number | number[] | Timestamps
}

/**
 * Optional sibling-keyring projection returned by `GET /pull/...?withKeyring=1`.
 * Author fields are dropped — the keyring document is unsigned in this model.
 */
export interface PullKeyringProjection {
  data: Record<string, unknown>
  hash: string
  timestamp: number
}

/** Response from a pull request. */
export interface PullResult {
  data: Record<string, unknown>
  hash: string
  timestamp: number
  authorPubkey?: string
  authorSignature?: string
  /**
   * Present only when the request URL set `?withKeyring=1` (or the client
   * called `pull(path, {withKeyring: true})`). `null` means the keyring
   * document does not exist at `<collection>/_keyring`; an object means it
   * was fetched alongside the data doc in the same round-trip.
   */
  keyring?: PullKeyringProjection | null
}

/** Response from a successful push. */
export interface PushSuccess {
  hash: string
  timestamp: number
}
