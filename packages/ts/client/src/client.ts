import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"
import type {
  StarfishClientOptions,
  AuthProvider,
} from "./types.js"
import { ConflictError, StarfishHttpError } from "./types.js"

const APPEND_DEFAULT_FIELD = "items"

/** Result of pulling a binary blob from the server. */
export interface BlobPullResult {
  data: ArrayBuffer
  /** Content hash from the ETag header. Null if the server didn't include an ETag. */
  hash: string | null
  contentType: string
}

/** Result of pushing a binary blob to the server. */
export interface BlobPushResult {
  hash: string
}

/** Options for append-only pull — extracts a single array field from the response. */
export interface AppendPullOptions {
  /** Array field name in `data`. Defaults to `"items"`. */
  appendField?: string
  /** Only return items appended after this timestamp (ms). Sent as `?checkpoint=`. */
  since?: number
  /** Return only the last K items (applied after `since` filter). Sent as `?last=`. */
  last?: number
}

/**
 * Low-level HTTP client for the Starfish sync protocol.
 * Handles auth headers and response parsing.
 */
export class StarfishClient {
  private readonly baseUrl: string
  private readonly auth?: AuthProvider
  private readonly fetch: typeof globalThis.fetch

  constructor(options: StarfishClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "")
    this.auth = options.auth
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /** Pull synced data from the server. Returns the raw `PullResult`. */
  async pull(path: string, checkpoint?: number): Promise<PullResult>
  /** Pull an append-only collection. Extracts and returns `data[appendField]` as `T[]`. */
  async pull<T = unknown>(path: string, options: AppendPullOptions): Promise<T[]>
  async pull<T = unknown>(
    path: string,
    checkpointOrOptions?: number | AppendPullOptions,
  ): Promise<PullResult | T[]> {
    let url = `${this.baseUrl}${path}`
    let appendField: string | undefined

    if (typeof checkpointOrOptions === "number") {
      if (checkpointOrOptions) url += `?checkpoint=${checkpointOrOptions}`
    } else if (checkpointOrOptions != null) {
      appendField = checkpointOrOptions.appendField ?? APPEND_DEFAULT_FIELD
      const params = new URLSearchParams()
      if (checkpointOrOptions.since != null) {
        if (checkpointOrOptions.since < 0) throw new Error("since must be non-negative")
        params.set("checkpoint", String(checkpointOrOptions.since))
      }
      if (checkpointOrOptions.last != null) {
        if (checkpointOrOptions.last < 0) throw new Error("last must be non-negative")
        params.set("last", String(checkpointOrOptions.last))
      }
      if (params.size > 0) url += `?${params.toString()}`
    }

    const authHeaders = this.auth
      ? await this.auth({ method: "GET", path, body: null })
      : {}

    const res = await this.fetch(url, {
      method: "GET",
      headers: { Accept: "application/json", ...authHeaders },
    })
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }

    const result = await res.json() as PullResult
    if (appendField !== undefined) {
      const list = (result.data as Record<string, unknown> | null)?.[appendField]
      return (Array.isArray(list) ? list : []) as T[]
    }
    return result
  }

  /**
   * Push synced data to the server.
   * @param path - The push endpoint path (e.g. "/push/users/abc/settings")
   * @param data - The full document data to push
   * @param baseHash - Hash of the document this push is based on (null for first push)
   * @param authorSignature - Optional author signature for provenance
   * @throws {ConflictError} if the server detects a hash mismatch (409)
   */
  async push(
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
    authorSignature?: string
  ): Promise<PushSuccess> {
    const body = JSON.stringify({
      data,
      baseHash,
      ...(authorSignature && { authorSignature }),
    })

    const authHeaders = this.auth
      ? await this.auth({ method: "POST", path, body })
      : {}

    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...authHeaders,
      },
      body,
    })

    if (res.status === 409) {
      throw new ConflictError()
    }
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }
    return res.json() as Promise<PushSuccess>
  }

  /**
   * Pull binary data from a blob collection.
   * Returns raw bytes with the content hash from the ETag header.
   */
  async pullBlob(path: string): Promise<BlobPullResult> {
    const authHeaders = this.auth
      ? await this.auth({ method: "GET", path, body: null })
      : {}

    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "GET",
      headers: { Accept: "*/*", ...authHeaders },
    })
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }

    const etag = res.headers.get("ETag")?.replace(/"/g, "") ?? null
    const contentType = res.headers.get("Content-Type") ?? "application/octet-stream"
    const data = await res.arrayBuffer()

    return { data, hash: etag, contentType }
  }

  /**
   * Push binary data to a blob collection.
   * Binary collections use last-write-wins (no conflict detection).
   */
  async pushBlob(
    path: string,
    data: ArrayBuffer | Uint8Array | Blob,
    contentType: string,
  ): Promise<BlobPushResult> {
    const authHeaders = this.auth
      ? await this.auth({ method: "POST", path, body: null })
      : {}

    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": contentType,
        Accept: "application/json",
        ...authHeaders,
      },
      body: data as BodyInit,
    })
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }
    return res.json() as Promise<BlobPushResult>
  }
}
