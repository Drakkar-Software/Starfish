import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"
import {
  DEFAULT_ALG,
  signRequest,
  stableStringify,
  type SignableMethod,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import type {
  StarfishClientOptions,
  StarfishCapProvider,
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
 * Options for a structured (non-append) pull.
 *
 * `withKeyring: true` appends `?withKeyring=1` so the server includes the
 * collection's sibling `<collection>/_keyring` document in the response,
 * saving a cold-start round-trip. The cap-cert scope MUST cover BOTH the
 * data path and `<collection>/_keyring` — `scopes.writer(collection)` denies
 * the keyring path and will produce a 403; use `scopes.readWrite()` or grant
 * the keyring path explicitly when opting in.
 */
export interface PullOptions {
  /** Server timestamp of the last successful pull (ms). Sent as `?checkpoint=`. */
  checkpoint?: number
  /** Include the sibling `_keyring` document in the response. Defaults to false. */
  withKeyring?: boolean
}

/**
 * Base64-encode the canonical stable-stringification of a cap-cert.
 *
 * Used as the value of the `Authorization: Cap <…>` header in v3.0. We rely
 * on the host's `btoa` for browsers and fall back to `Buffer` in Node so the
 * client stays free of native dependencies.
 */
function encodeCapAuth(cap: unknown): string {
  const json = stableStringify(cap as Record<string, unknown>)
  if (typeof btoa === "function") {
    return btoa(json)
  }
  const bufCtor = (globalThis as { Buffer?: { from: (s: string, enc: string) => { toString: (enc: string) => string } } }).Buffer
  if (bufCtor) return bufCtor.from(json, "utf-8").toString("base64")
  throw new Error("No base64 encoder available")
}

/**
 * Low-level HTTP client for the Starfish sync protocol.
 * Handles auth headers and response parsing.
 */
export class StarfishClient {
  private readonly baseUrl: string
  private readonly capProvider?: StarfishCapProvider
  private readonly fetch: typeof globalThis.fetch
  /**
   * Installed client-side plugins. Currently stored as inert data; no
   * hooks fire yet. Extensions can inspect this list if needed.
   */
  public readonly plugins: ReadonlyArray<import("./types.js").ClientPlugin>

  constructor(options: StarfishClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "")
    this.capProvider = options.capProvider
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
    this.plugins = options.plugins ? [...options.plugins] : []
  }

  /**
   * Resolve the host portion of the URL the client will send to. The host
   * is folded into the signed canonical input as the `h` field so the
   * server can refuse a signature that was minted against a different
   * Starfish host (replay-across-servers defence).
   *
   * When `baseUrl` is relative — e.g. the consumer passed a custom `fetch`
   * that resolves relative URLs in its own context — there is no parseable
   * host; we return `""` so signing still proceeds. The server-side
   * verifier will also reconstruct host from its inbound URL, so the
   * empty-host case still verifies symmetrically when both sides agree.
   */
  private signingHost(): string {
    try {
      return new URL(this.baseUrl).host
    } catch {
      return ""
    }
  }

  /**
   * Build auth headers for a request. When a `capProvider` is set, signs the
   * request with the device's Ed25519 private key and returns the v3 header
   * set (`Authorization: Cap …`, `X-Starfish-Sig`, `X-Starfish-Ts`,
   * `X-Starfish-Nonce`). Empty when no provider is configured (public reads).
   *
   * Body bytes signed MUST equal the bytes sent on the wire — callers pass
   * the already-serialized body string here so signing and transmission agree.
   * The host bound into the signature is derived from `baseUrl` once per call.
   */
  private async buildAuthHeaders(
    method: SignableMethod,
    pathAndQuery: string,
    body: string | undefined,
  ): Promise<Record<string, string>> {
    if (this.capProvider) {
      const { cap, devEdPrivHex, pubHex, presenterAlg } = await this.capProvider.getCap()
      const req: SignableRequest = {
        method,
        pathAndQuery,
        body,
        host: this.signingHost(),
      }
      // The signing suite is the suite of whoever holds `devEdPrivHex`:
      // - device/member: the subject signs, so use the cert's subject suite.
      //   Tolerant-reader rule (matches the server resolver): an absent
      //   `subAlg` means "same suite as the issuer", so fall back to
      //   `cap.issAlg`, not the global default.
      // - audience (public-link): the presenter is an arbitrary redeemer
      //   signing with their own key, unrelated to the cert's suites, so use
      //   `presenterAlg` (defaulting to ed25519). The server reads it back from
      //   `X-Starfish-Alg` for audience caps.
      const signAlg =
        cap.kind === "audience" ? (presenterAlg ?? DEFAULT_ALG) : (cap.subAlg ?? cap.issAlg)
      const { alg, sig, ts, nonce } = await signRequest(req, devEdPrivHex, {
        alg: signAlg,
      })
      const headers: Record<string, string> = {
        Authorization: `Cap ${encodeCapAuth(cap)}`,
        "X-Starfish-Sig": sig,
        "X-Starfish-Ts": String(ts),
        "X-Starfish-Nonce": nonce,
        "X-Starfish-Alg": alg,
      }
      // Audience (public-link) caps bind no single subject, so the server needs
      // the presenter's pubkey to verify the signature and check the allow-list.
      if (pubHex !== undefined) headers["X-Starfish-Pub"] = pubHex
      return headers
    }
    return {}
  }

  /** Pull synced data from the server. Returns the raw `PullResult`. */
  async pull(path: string, checkpoint?: number): Promise<PullResult>
  /** Pull synced data with structured options (e.g. `{withKeyring: true}`). */
  async pull(path: string, options: PullOptions): Promise<PullResult>
  /** Pull an append-only collection. Extracts and returns `data[appendField]` as `T[]`. */
  async pull<T = unknown>(path: string, options: AppendPullOptions): Promise<T[]>
  async pull<T = unknown>(
    path: string,
    checkpointOrOptions?: number | AppendPullOptions | PullOptions,
  ): Promise<PullResult | T[]> {
    let pathAndQuery = path
    let appendField: string | undefined

    if (typeof checkpointOrOptions === "number") {
      if (checkpointOrOptions) pathAndQuery += `?checkpoint=${checkpointOrOptions}`
    } else if (checkpointOrOptions != null) {
      // Disambiguate AppendPullOptions vs PullOptions.
      //
      // PullOptions are identified by the presence of `withKeyring` or
      // `checkpoint` keys (which AppendPullOptions does not have — append
      // uses `since`, not `checkpoint`). Anything else, including an empty
      // `{}` object, retains the historical behavior of AppendPullOptions
      // (extracts `data.items` with `?` query).
      const opts = checkpointOrOptions as AppendPullOptions & PullOptions
      const isPullOptions =
        opts.withKeyring !== undefined || opts.checkpoint !== undefined
      const params = new URLSearchParams()

      if (isPullOptions) {
        if (opts.checkpoint != null && opts.checkpoint > 0) {
          params.set("checkpoint", String(opts.checkpoint))
        }
        if (opts.withKeyring) {
          params.set("withKeyring", "1")
        }
      } else {
        appendField = opts.appendField ?? APPEND_DEFAULT_FIELD
        if (opts.since != null) {
          if (opts.since < 0) throw new Error("since must be non-negative")
          params.set("checkpoint", String(opts.since))
        }
        if (opts.last != null) {
          if (opts.last < 0) throw new Error("last must be non-negative")
          params.set("last", String(opts.last))
        }
      }
      if (params.size > 0) pathAndQuery += `?${params.toString()}`
    }

    const url = `${this.baseUrl}${pathAndQuery}`
    const authHeaders = await this.buildAuthHeaders("GET", pathAndQuery, undefined)

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
   *
   * v3 author fields (`authorPubkey` + `authorSignature`) live inside `data`
   * and are produced by `SyncManager` when a `signer` is configured.
   * @throws {ConflictError} if the server detects a hash mismatch (409)
   */
  async push(
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
  ): Promise<PushSuccess> {
    const body = JSON.stringify({
      data,
      baseHash,
    })

    const authHeaders = await this.buildAuthHeaders("POST", path, body)

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
   * Append an element to an appendOnly (`by_timestamp`) collection.
   *
   * Unlike {@link push}, appendOnly writes carry no hash/conflict check — an
   * authorized append is always accepted. Each element is stored server-side as
   * `{ts, data}` and pulls can filter by `ts` via `since`/`checkpoint`.
   *
   * @param path - the push endpoint (e.g. "/push/events")
   * @param data - the element payload. For a `delegated` collection, encrypt it
   *   first (e.g. `createKeyringEncryptor(keyring, kem).encrypt(data)`); the
   *   server stores it opaquely and never reads it.
   * @param opts.ts - optional client-supplied element timestamp (ms). Must be a
   *   non-negative integer strictly greater than the latest stored element's ts
   *   (else the server responds 409). Omit to let the server assign one.
   * @throws {StarfishHttpError} on a non-2xx response (e.g. 409 for a
   *   non-monotonic timestamp).
   */
  async append(
    path: string,
    data: Record<string, unknown>,
    opts: { ts?: number } = {},
  ): Promise<PushSuccess> {
    const bodyObj: Record<string, unknown> = { data }
    if (opts.ts !== undefined) bodyObj["ts"] = opts.ts
    const body = JSON.stringify(bodyObj)

    const authHeaders = await this.buildAuthHeaders("POST", path, body)

    const res = await this.fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...authHeaders,
      },
      body,
    })

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
    const authHeaders = await this.buildAuthHeaders("GET", path, undefined)

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
    // Blobs are not JSON; we leave body undefined when signing — server-side
    // verification is expected to use a separate path for blob uploads.
    const authHeaders = await this.buildAuthHeaders("POST", path, undefined)

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
