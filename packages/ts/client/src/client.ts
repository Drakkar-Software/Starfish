import type { PullResult, PushSuccess } from "@drakkar.software/starfish-protocol"
import {
  AUTHOR_PUBKEY_FIELD,
  AUTHOR_SIGNATURE_FIELD,
  DATA_FIELD,
  TS_FIELD,
  BASE_HASH_FIELD,
  PUSH_PATH_PREFIX,
  HEADER_AUTHORIZATION,
  HEADER_SIG,
  HEADER_TS,
  HEADER_NONCE,
  HEADER_ALG,
  HEADER_PUB,
  HEADER_CONTENT_TYPE,
  HEADER_ACCEPT,
  DEFAULT_ALG,
  signAppendAuthor,
  signRequest,
  stableStringify,
  type AppendAuthor,
  type SignableMethod,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import type {
  StarfishClientOptions,
  StarfishCapProvider,
} from "./types.js"
import { ConflictError, StarfishHttpError } from "./types.js"

const APPEND_DEFAULT_FIELD = "items"

/** The storage `documentKey` for a push `path`: the path with the `/push/`
 *  action prefix stripped (the namespace lives only in the URL). The author
 *  signature binds to this key. */
export function stripPushPrefix(path: string): string {
  return path.startsWith(PUSH_PATH_PREFIX) ? path.slice(PUSH_PATH_PREFIX.length) : path
}

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

/** Per-collection result in a {@link BatchPullResult}: either the pulled
 *  document (`data`/`hash`/`timestamp`) or a per-collection `error` string. */
export interface BatchPullEntry {
  data?: unknown
  hash?: string
  timestamp?: number
  error?: string
}

/** Response of {@link StarfishClient.batchPull}: a map of requested collection
 *  name → an ARRAY of {@link BatchPullEntry}, one per requested param-set, in
 *  request order. A collection read with no params yields a one-element array. */
export interface BatchPullResult {
  collections: Record<string, BatchPullEntry[]>
}

/** Options for {@link StarfishClient.batchPull}. */
export interface BatchPullOptions {
  /** Per-collection path params: collection name → an ARRAY of param-sets, one
   *  per document to read from that collection, e.g.
   *  `{ profile: [{ identity: "a" }, { identity: "b" }] }` reads two profiles in
   *  one round-trip. Serialized to a URL-encoded JSON `params` query. The
   *  `{identity}` param is auto-filled by the server from the authenticated
   *  caller when a set omits it, so a single self-doc read can pass `[{}]` — or
   *  omit the collection from `params` entirely (an unlisted collection reads one
   *  auto-filled doc). Results come back under the same name in request order. */
  params?: Record<string, Record<string, string>[]>
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
  private readonly namespace?: string
  private readonly capProvider?: StarfishCapProvider
  private readonly fetch: typeof globalThis.fetch
  /**
   * Installed client-side plugins. Currently stored as inert data; no
   * hooks fire yet. Extensions can inspect this list if needed.
   */
  public readonly plugins: ReadonlyArray<import("./types.js").ClientPlugin>

  constructor(options: StarfishClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "")
    // Empty string ⇒ no namespace (treat like unset), so a falsy env value
    // doesn't produce a malformed `/v1//…` path.
    this.namespace = options.namespace || undefined
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
   * Rewrite a request path for the configured namespace. A no-op when no
   * namespace is set; otherwise `/{action}/…` becomes `/v1/{namespace}/{action}/…`
   * (the `/v1` protocol-version segment is part of the namespaced route, matching
   * the Python client and the server's namespace mount).
   *
   * Applied to the path used for BOTH the signature and the URL so the canonical
   * path the client signs equals the path the server reconstructs from the URL.
   * Covers SDK-helper-built paths too — that's the point: a namespace-unaware
   * helper passing `/push/spaces/x/_keyring` reaches `/v1/{ns}/push/spaces/x/_keyring`.
   */
  private applyNamespace(path: string): string {
    return this.namespace ? `/v1/${this.namespace}${path}` : path
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
    if (!this.capProvider) return {}
    const capCtx = await this.capProvider.getCap()
    return this.capRequestHeaders(capCtx, method, pathAndQuery, body)
  }

  /**
   * Build the request-signing headers from an ALREADY-fetched cap context. Split
   * out of {@link buildAuthHeaders} so {@link append} can fetch the cap once and
   * reuse it for BOTH the author signature (over the element data) and the
   * request signature (over the body), without redeeming the cap twice — a
   * second `getCap()` could rotate keys and break the `authorPubkey ===
   * presenter` bind the server checks.
   */
  private async capRequestHeaders(
    capCtx: Awaited<ReturnType<StarfishCapProvider["getCap"]>>,
    method: SignableMethod,
    pathAndQuery: string,
    body: string | undefined,
  ): Promise<Record<string, string>> {
    const { cap, devEdPrivHex, pubHex, presenterAlg } = capCtx
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
      [HEADER_AUTHORIZATION]: `Cap ${encodeCapAuth(cap)}`,
      [HEADER_SIG]: sig,
      [HEADER_TS]: String(ts),
      [HEADER_NONCE]: nonce,
      [HEADER_ALG]: alg,
    }
    // Audience (public-link) caps bind no single subject, so the server needs
    // the presenter's pubkey to verify the signature and check the allow-list.
    if (pubHex !== undefined) headers[HEADER_PUB] = pubHex
    return headers
  }

  /**
   * Resolve the author public key to attach to a signed append: the redeemer's
   * `pubHex` for an audience cap, else the cert subject `cap.sub` for a
   * device/member cap. This is the SAME key that signs the request, so a server
   * enforcing author proof can bind the stored element to its writer. Returns
   * undefined only for a (malformed) cap with neither — the append then goes
   * unsigned and a server requiring signatures rejects it.
   */
  private appendAuthorKey(
    capCtx: Awaited<ReturnType<StarfishCapProvider["getCap"]>>,
  ): { authorPubHex: string; signAlg: typeof DEFAULT_ALG } | null {
    const { cap, pubHex, presenterAlg } = capCtx
    const authorPubHex = pubHex ?? cap.sub
    if (authorPubHex === undefined) return null
    const signAlg =
      cap.kind === "audience" ? (presenterAlg ?? DEFAULT_ALG) : (cap.subAlg ?? cap.issAlg)
    return { authorPubHex, signAlg }
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
    let pathAndQuery = this.applyNamespace(path)
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
      headers: { [HEADER_ACCEPT]: "application/json", ...authHeaders },
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
   * Pull several documents in one round-trip via `/batch/pull`. `collections` is
   * the list of distinct collection names; `opts.params` supplies, per collection,
   * an ARRAY of path-param sets — one per document to read — so the SAME collection
   * can fan in many documents (e.g. many users' `profile`) in a single request.
   * The server auto-fills the `{identity}` param from the authenticated caller for
   * any set that omits it, so a self-doc collection needs no params. Returns a map
   * of collection name → an ARRAY of pulled documents (or per-document `{ error }`),
   * in request order. Honors the configured namespace.
   *
   * For the common "many docs of one collection" case prefer {@link batchPullMany}.
   *
   * Note: not append/checkpoint-aware — for incremental append-only reads use
   * `pull(path, { since })` (or `AppendLogCursor`) per collection.
   */
  async batchPull(
    collections: string[],
    opts: BatchPullOptions = {},
  ): Promise<BatchPullResult> {
    const search = new URLSearchParams()
    search.set("collections", collections.join(","))
    if (opts.params && Object.keys(opts.params).length > 0) {
      search.set("params", JSON.stringify(opts.params))
    }
    const pathAndQuery = `${this.applyNamespace("/batch/pull")}?${search.toString()}`
    const url = `${this.baseUrl}${pathAndQuery}`
    const authHeaders = await this.buildAuthHeaders("GET", pathAndQuery, undefined)

    const res = await this.fetch(url, {
      method: "GET",
      headers: { [HEADER_ACCEPT]: "application/json", ...authHeaders },
    })
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }
    return await res.json() as BatchPullResult
  }

  /**
   * Convenience over {@link batchPull} for reading MANY documents of ONE
   * collection in a single round-trip: pass the per-document param-sets and get
   * back the {@link BatchPullEntry} array aligned to `paramsList` by index (each
   * entry is `{ data, hash, timestamp }` or `{ error }`). An empty `paramsList`
   * issues no request and returns `[]`.
   */
  async batchPullMany(
    collection: string,
    paramsList: Record<string, string>[],
  ): Promise<BatchPullEntry[]> {
    if (paramsList.length === 0) return []
    const res = await this.batchPull([collection], { params: { [collection]: paramsList } })
    return res.collections[collection] ?? []
  }

  /**
   * Push synced data to the server.
   * @param path - The push endpoint path (e.g. "/push/users/abc/settings")
   * @param data - The full document data to push
   * @param baseHash - Hash of the document this push is based on (null for first push)
   *
   * v3 author proof (`authorPubkey` + `authorSignature`) is passed via `author`
   * (produced by `SyncManager` when a `signer` is configured) and sent as
   * top-level body siblings of `data`, where the server verifies it.
   * @throws {ConflictError} if the server detects a hash mismatch (409)
   */
  async push(
    path: string,
    data: Record<string, unknown>,
    baseHash: string | null,
    author?: AppendAuthor,
  ): Promise<PushSuccess> {
    const body = JSON.stringify({
      [DATA_FIELD]: data,
      [BASE_HASH_FIELD]: baseHash,
      ...(author && {
        [AUTHOR_PUBKEY_FIELD]: author.authorPubkey,
        [AUTHOR_SIGNATURE_FIELD]: author.authorSignature,
      }),
    })

    const sendPath = this.applyNamespace(path)
    const authHeaders = await this.buildAuthHeaders("POST", sendPath, body)

    const res = await this.fetch(`${this.baseUrl}${sendPath}`, {
      method: "POST",
      headers: {
        [HEADER_CONTENT_TYPE]: "application/json",
        [HEADER_ACCEPT]: "application/json",
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
   * @throws {StarfishHttpError} on a non-2xx response — e.g. 409
   *   `{ error: "non_monotonic_timestamp" }` for a non-monotonic timestamp, or
   *   `{ error: "append_limit_exceeded", limit }` if the collection's `maxItems`
   *   cap is reached (partition by a path parameter for higher volume).
   */
  async append(
    path: string,
    data: Record<string, unknown>,
    opts: { ts?: number } = {},
  ): Promise<PushSuccess> {
    const sendPath = this.applyNamespace(path)
    const bodyObj: Record<string, unknown> = { [DATA_FIELD]: data }
    if (opts.ts !== undefined) bodyObj[TS_FIELD] = opts.ts

    // Author proof. Fetch the cap ONCE and reuse it for both the author
    // signature (over the element `data`) and the request signature (over the
    // final body) — see {@link capRequestHeaders}. The author fields are signed
    // with the same key that authenticates the request, so a collection with
    // `requireAuthorSignature` (the default) binds the stored element to its
    // writer. Without a cap provider the append is sent unsigned and such a
    // collection rejects it.
    const capCtx = this.capProvider ? await this.capProvider.getCap() : null
    if (capCtx) {
      const authorKey = this.appendAuthorKey(capCtx)
      if (authorKey) {
        // The signature binds the author to BOTH the element data AND the
        // document it is written to (the storage path = `path` minus the
        // `/push/` action prefix; the namespace lives only in the URL).
        const documentKey = stripPushPrefix(path)
        const { authorPubkey, authorSignature } = signAppendAuthor(
          documentKey,
          data,
          authorKey.authorPubHex,
          capCtx.devEdPrivHex,
          authorKey.signAlg,
        )
        bodyObj[AUTHOR_PUBKEY_FIELD] = authorPubkey
        bodyObj[AUTHOR_SIGNATURE_FIELD] = authorSignature
      }
    }

    const body = JSON.stringify(bodyObj)
    const authHeaders = capCtx
      ? await this.capRequestHeaders(capCtx, "POST", sendPath, body)
      : {}

    const res = await this.fetch(`${this.baseUrl}${sendPath}`, {
      method: "POST",
      headers: {
        [HEADER_CONTENT_TYPE]: "application/json",
        [HEADER_ACCEPT]: "application/json",
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
    const sendPath = this.applyNamespace(path)
    const authHeaders = await this.buildAuthHeaders("GET", sendPath, undefined)

    const res = await this.fetch(`${this.baseUrl}${sendPath}`, {
      method: "GET",
      headers: { [HEADER_ACCEPT]: "*/*", ...authHeaders },
    })
    if (!res.ok) {
      throw new StarfishHttpError(res.status, await res.text())
    }

    const etag = res.headers.get("ETag")?.replace(/"/g, "") ?? null
    const contentType = res.headers.get(HEADER_CONTENT_TYPE) ?? "application/octet-stream"
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
    const sendPath = this.applyNamespace(path)
    const authHeaders = await this.buildAuthHeaders("POST", sendPath, undefined)

    const res = await this.fetch(`${this.baseUrl}${sendPath}`, {
      method: "POST",
      headers: {
        [HEADER_CONTENT_TYPE]: contentType,
        [HEADER_ACCEPT]: "application/json",
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
