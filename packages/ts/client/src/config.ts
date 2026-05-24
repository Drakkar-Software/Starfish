/** Encryption modes supported by the Starfish server. */
export type EncryptionMode = "none" | "delegated"

/** Append-only configuration exposed via GET /config. */
export interface AppendOnlyClientInfo {
  /** Append-only strategy. Only `"by_timestamp"` is currently supported. */
  type: "by_timestamp"
  /** Array field name in the stored document. Defaults to "items". */
  field?: string
  /** false = no storage write (replaces queueOnly). true/absent = append to array. */
  persist?: boolean
}

/** Append-only configuration exposed via GET /config. */
export interface AppendOnlyClientInfo {
  /** Array field name in the stored document. Defaults to "items". */
  field?: string
  /** false = no storage write (replaces queueOnly). true/absent = append to array. */
  persist?: boolean
  /** When true, server validates client's baseHash against hash(lastItem). */
  checkLastItem?: boolean
}

/** Per-collection metadata returned by GET /config. */
export interface CollectionClientInfo {
  name: string
  maxBodyBytes: number
  encryption: EncryptionMode
  allowedMimeTypes: string[]
  pullOnly?: boolean
  pushOnly?: boolean
  appendOnly?: AppendOnlyClientInfo
  ttlMs?: number
  forceFullFetch?: boolean
}

/** Response shape of GET /config. */
export interface ConfigResponse {
  collections: CollectionClientInfo[]
  namespaces?: Record<string, { collections: CollectionClientInfo[] }>
}

/**
 * Fetch the server's collection manifest from GET /config.
 *
 * @param baseUrl - Base URL of the Starfish server (e.g. `"https://api.example.com/v1"`).
 * @param options.headers - Optional request headers (e.g. `Authorization`).
 * @throws {Error} if the server returns a non-2xx response.
 */
export async function fetchServerConfig(
  baseUrl: string,
  options?: { headers?: Record<string, string> },
): Promise<ConfigResponse> {
  const url = `${baseUrl.replace(/\/$/, "")}/config`
  const res = await fetch(url, {
    method: "GET",
    headers: options?.headers,
  })
  if (!res.ok) {
    throw new Error(`fetchServerConfig: ${res.status} ${res.statusText}`)
  }
  return res.json() as Promise<ConfigResponse>
}
