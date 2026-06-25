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
  HEADER_PUB,
  HEADER_CONTENT_TYPE,
  HEADER_ACCEPT,
  PARQUET_MIME_TYPE as PARQUET_MIME_TYPE_VALUE,
  PARQUET_MIME_TYPES as PARQUET_MIME_TYPES_VALUE,
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
  PullCache,
} from "./types.js"
import { AppendHttpError, ConflictError, StarfishHttpError } from "./types.js"
import { parseRetryAfterMs } from "./fetch.js"

const APPEND_DEFAULT_FIELD = "items"
const MAX_REVALIDATE_ATTEMPTS = 5
const REVALIDATE_INITIAL_DELAY_MS = 1_000
const REVALIDATE_MAX_DELAY_MS = 30_000

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Shape persisted in a {@link PullCache} for one document: the raw server
 * `PullResult` fields. For E2E collections `data` is the sealed ciphertext.
 */
interface CachedPull {
  data: Record<string, unknown>
  hash: string
  timestamp: number
  /** Wall-clock ms when this snapshot was written — for {@link StarfishClientOptions.cacheMaxAgeMs} expiry. */
  cachedAt: number
}

/**
 * The cache key for a pull `pathAndQuery`: the path with any query string
 * dropped, so a checkpoint'd or `withKeyring` pull and a plain pull of the same
 * document share one stable key (the document identity, not the request shape).
 */
function pullCacheKey(pathAndQuery: string): string {
  const q = pathAndQuery.indexOf("?")
  return q === -1 ? pathAndQuery : pathAndQuery.slice(0, q)
}

/**
 * Whether a {@link PullResult} was served from the offline read-through cache
 * (the transport was unreachable) rather than a live server response. Used by
 * {@link SyncManager} to surface a `stale` flag to the UI without treating a
 * cache hit as proof the server is reachable.
 */
export function pullWasFromCache(result: PullResult): boolean {
  return (result as { fromCache?: boolean }).fromCache === true
}

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
  /** Return only the last K items. Alias of `last`; sent as `?limit=`. When both
   *  are given, `limit` wins. */
  limit?: number
  /** Explicitly fetch the whole collection (sent as `?full=true`). Mutually
   *  exclusive with `since`/`limit`/`last` — the server requires a pull to declare
   *  exactly one of {checkpoint, limit/last, full}. */
  full?: boolean
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
  /**
   * Serve the last-synced cached snapshot immediately (tagged via
   * {@link pullWasFromCache}) and revalidate in the background. Requires a
   * {@link StarfishClientOptions.cache} to be configured; without one the option
   * is a no-op and the pull goes to the network as usual.
   *
   * On a cache hit: returns the stale snapshot at once, kicks a background fetch,
   * and on success writes the fresh snapshot to cache and fires
   * {@link StarfishClientOptions.onRevalidated}. Uses the same dedup set as the
   * {@link StarfishClientOptions.cacheFallbackStatuses} revalidation path — a
   * concurrent error-triggered loop for the same document is not duplicated.
   *
   * On a cache miss: falls through to the normal network-first pull unchanged.
   */
  staleWhileRevalidate?: boolean
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
  /**
   * Per-collection append options, index-aligned to `params`. Makes the batch
   * request **append/checkpoint-aware**: each entry returns the bounded tail of
   * that collection's append-only log rather than the full document.
   *
   * Serialized as URL-encoded JSON alongside `params`. Server ignores it for
   * collections that are not append-only (returns `{ error: "append_params_not_supported" }`
   * for those entries). `full` is disallowed in batch (`full_not_allowed` per entry).
   *
   * Example — read the last 5 events for two rooms and the newest item for a third:
   * ```ts
   * await client.batchPull(["events"], {
   *   params: { events: [{ room: "a" }, { room: "b" }, { room: "c" }] },
   *   appendParams: { events: [{ last: 5 }, { last: 5 }, { last: 1 }] },
   * })
   * ```
   * Each `data[appendField]` in the result is the filtered array for that entry.
   */
  appendParams?: Record<string, AppendPullOptions[]>
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
  private readonly cache?: PullCache
  private readonly cacheMaxAgeMs?: number
  private readonly cacheFallbackStatuses?: ReadonlyArray<number>
  private readonly onRevalidated?: (path: string, result: PullResult) => void
  private readonly revalidating = new Set<string>()
  /**
   * In-memory mirror of the latest document timestamp written to each cache
   * key via {@link writeCache}. Updated synchronously so {@link revalidateLoop}
   * can guard against stale overwrites without an extra async cache read.
   */
  private readonly latestCacheTimestamp = new Map<string, number>()
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
    this.cache = options.cache
    this.cacheMaxAgeMs = options.cacheMaxAgeMs
    this.cacheFallbackStatuses = options.cacheFallbackStatuses
    this.onRevalidated = options.onRevalidated
    this.plugins = options.plugins ? [...options.plugins] : []
  }

  /**
   * Mark a `PullResult` as having been served from the offline read-through
   * cache (transport was unreachable). Non-enumerable so it doesn't leak into
   * JSON / equality / re-caching; read via {@link pullWasFromCache}.
   */
  private tagFromCache(result: PullResult): PullResult {
    Object.defineProperty(result, "fromCache", { value: true, enumerable: false })
    return result
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
    const { cap, devEdPrivHex, pubHex } = capCtx
    const req: SignableRequest = {
      method,
      pathAndQuery,
      body,
      host: this.signingHost(),
    }
    const { sig, ts, nonce } = await signRequest(req, devEdPrivHex)
    const headers: Record<string, string> = {
      [HEADER_AUTHORIZATION]: `Cap ${encodeCapAuth(cap)}`,
      [HEADER_SIG]: sig,
      [HEADER_TS]: String(ts),
      [HEADER_NONCE]: nonce,
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
  ): { authorPubHex: string } | null {
    const { cap, pubHex } = capCtx
    const authorPubHex = pubHex ?? cap.sub
    if (authorPubHex === undefined) return null
    return { authorPubHex }
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
    let swr = false

    if (typeof checkpointOrOptions === "number") {
      if (checkpointOrOptions) pathAndQuery += `?checkpoint=${checkpointOrOptions}`
    } else if (checkpointOrOptions != null) {
      // Disambiguate AppendPullOptions vs PullOptions.
      //
      // PullOptions are identified by the presence of `withKeyring`, `checkpoint`,
      // or `staleWhileRevalidate` keys (which AppendPullOptions does not have —
      // append uses `since`, not `checkpoint`). Anything else, including an empty
      // `{}` object, retains the historical behavior of AppendPullOptions
      // (extracts `data.items` with `?` query).
      const opts = checkpointOrOptions as AppendPullOptions & PullOptions
      const isPullOptions =
        opts.withKeyring !== undefined ||
        opts.checkpoint !== undefined ||
        opts.staleWhileRevalidate !== undefined
      const params = new URLSearchParams()

      if (isPullOptions) {
        if (opts.checkpoint != null && opts.checkpoint > 0) {
          params.set("checkpoint", String(opts.checkpoint))
        }
        if (opts.withKeyring) {
          params.set("withKeyring", "1")
        }
        swr = opts.staleWhileRevalidate === true
      } else {
        appendField = opts.appendField ?? APPEND_DEFAULT_FIELD
        // `full` means "the whole collection" — it cannot be combined with a bound.
        if (opts.full && (opts.since != null || opts.limit != null || opts.last != null)) {
          throw new Error("full cannot be combined with since, limit, or last")
        }
        if (opts.since != null) {
          if (opts.since < 0) throw new Error("since must be non-negative")
          params.set("checkpoint", String(opts.since))
        }
        if (opts.limit != null) {
          if (opts.limit < 0) throw new Error("limit must be non-negative")
          params.set("limit", String(opts.limit))
        }
        if (opts.last != null) {
          if (opts.last < 0) throw new Error("last must be non-negative")
          params.set("last", String(opts.last))
        }
        if (opts.full) {
          params.set("full", "true")
        }
      }
      if (params.size > 0) pathAndQuery += `?${params.toString()}`
    }

    const url = `${this.baseUrl}${pathAndQuery}`
    const authHeaders = await this.buildAuthHeaders("GET", pathAndQuery, undefined)

    // Read-through cache: only for structured (non-append) pulls. Append
    // collections own their own warm-start persistence via AppendLogCursor.
    const cacheKey =
      this.cache && appendField === undefined ? pullCacheKey(pathAndQuery) : undefined

    // staleWhileRevalidate: serve the cached snapshot immediately (cache-first
    // paint without a zustand store), kick background revalidation, return stale.
    // Falls through to network-first when there is no cache hit (miss or expired).
    if (swr && cacheKey) {
      const cached = await this.readCache(cacheKey)
      if (cached) {
        this.scheduleRevalidate(cacheKey, pathAndQuery, null, /* immediate */ true)
        return cached
      }
    }

    let res: Response
    try {
      res = await this.fetch(url, {
        method: "GET",
        headers: { [HEADER_ACCEPT]: "application/json", ...authHeaders },
      })
    } catch (err) {
      // The TRANSPORT failed (offline / DNS / timeout) — fall back to the last
      // cached snapshot for this document if we have one, tagged so callers can
      // tell it's stale. A real HTTP error (below) is a genuine server answer
      // and never gets here; 403 and 404 always propagate. 429 and 5xx
      // propagate by default too, but can fall back to cache when
      // `cacheFallbackStatuses` is set — see the stale-while-revalidate branch.
      if (cacheKey) {
        const cached = await this.readCache(cacheKey)
        if (cached) return cached
      }
      throw err
    }
    if (!res.ok) {
      const status = res.status
      if (cacheKey && this.cacheFallbackStatuses?.includes(status)) {
        // Stale-while-revalidate: serve the last-synced snapshot immediately and
        // retry in the background. 403/404 are not in the configured set so they
        // still propagate as genuine answers.
        const retryAfterHeader = res.headers.get("Retry-After")
        this.scheduleRevalidate(cacheKey, pathAndQuery, retryAfterHeader)
        const cached = await this.readCache(cacheKey)
        if (cached) {
          // Discard the response body so the underlying connection can be reused.
          void res.body?.cancel()
          return cached
        }
      }
      throw new StarfishHttpError(status, await res.text())
    }

    const result = await res.json() as PullResult
    if (appendField !== undefined) {
      const list = (result.data as Record<string, unknown> | null)?.[appendField]
      return (Array.isArray(list) ? list : []) as T[]
    }
    if (cacheKey) this.writeCache(cacheKey, result)
    return result
  }

  /**
   * Write a pull snapshot to the cache. Fire-and-forget; errors are swallowed
   * so a failing cache never blocks the caller. No-op when no cache is configured.
   */
  private writeCache(
    cacheKey: string,
    result: { data: Record<string, unknown>; hash: string; timestamp: number },
  ): void {
    if (!this.cache) return
    // Track the newest document timestamp written so revalidateLoop can check
    // staleness synchronously (without an async cache read adding extra ticks).
    if (result.timestamp > (this.latestCacheTimestamp.get(cacheKey) ?? -1)) {
      this.latestCacheTimestamp.set(cacheKey, result.timestamp)
    }
    const snapshot: CachedPull = {
      data: result.data,
      hash: result.hash,
      timestamp: result.timestamp,
      cachedAt: Date.now(),
    }
    void this.cache.set(cacheKey, JSON.stringify(snapshot)).catch(() => {})
  }

  /** Build the URL + auth headers for one revalidation GET. Shared between
   *  {@link pull} and {@link revalidateLoop} to avoid duplicated fetch setup. */
  private async revalidateFetch(pathAndQuery: string): Promise<Response> {
    const url = `${this.baseUrl}${pathAndQuery}`
    const authHeaders = await this.buildAuthHeaders("GET", pathAndQuery, undefined)
    return this.fetch(url, {
      method: "GET",
      headers: { [HEADER_ACCEPT]: "application/json", ...authHeaders },
    })
  }

  /**
   * Deduplicated fire-and-forget: starts one revalidation loop per cacheKey.
   * Used by both the {@link cacheFallbackStatuses} error path (delayed first
   * attempt, honoring `Retry-After`) and the {@link PullOptions.staleWhileRevalidate}
   * read path (`immediate: true` — no initial delay on the first attempt). The
   * `revalidating` set deduplicates across both triggers so a concurrent
   * error-triggered loop and an SWR-on-read loop for the same key collapse to one.
   */
  private scheduleRevalidate(
    cacheKey: string,
    pathAndQuery: string,
    retryAfterHeader: string | null,
    immediate = false,
  ): void {
    if (this.revalidating.has(cacheKey)) return
    this.revalidating.add(cacheKey)
    void this.revalidateLoop(cacheKey, pathAndQuery, retryAfterHeader, immediate).finally(() => {
      this.revalidating.delete(cacheKey)
    })
  }

  /**
   * Background revalidation loop shared by both {@link cacheFallbackStatuses}
   * hits and {@link PullOptions.staleWhileRevalidate} reads.
   *
   * Retries (honoring `Retry-After`) up to {@link MAX_REVALIDATE_ATTEMPTS} times.
   * When `immediate` is true the first attempt fires without any initial delay
   * (SWR-on-read path). On a live 2xx the fresh snapshot is written to cache and
   * {@link onRevalidated} fires. Stops early on a non-fallback status (403/404).
   */
  private async revalidateLoop(
    cacheKey: string,
    pathAndQuery: string,
    firstRetryAfter: string | null,
    immediate = false,
  ): Promise<void> {
    let retryAfterHeader = firstRetryAfter
    const fallbackSet = this.cacheFallbackStatuses ? new Set(this.cacheFallbackStatuses) : null
    for (let attempt = 0; attempt < MAX_REVALIDATE_ATTEMPTS; attempt++) {
      // Skip the initial delay for the first attempt when immediate mode is set
      // (staleWhileRevalidate path). Subsequent attempts always backoff normally.
      if (!immediate || attempt > 0) {
        const delay = parseRetryAfterMs(retryAfterHeader, {
          fallbackMs: Math.min(
            REVALIDATE_INITIAL_DELAY_MS * Math.pow(2, attempt),
            REVALIDATE_MAX_DELAY_MS,
          ),
          maxMs: REVALIDATE_MAX_DELAY_MS,
        })
        await sleep(delay)
      }

      try {
        const res = await this.revalidateFetch(pathAndQuery)

        if (res.ok) {
          const result = (await res.json()) as PullResult
          // Guard against stale overwrites: if push() wrote a newer snapshot
          // while this revalidation was in-flight, the in-memory tracker
          // reflects the current latest-written timestamp synchronously (no
          // extra async tick). We drop the revalidation result and leave the
          // cache — and onRevalidated — untouched so the pushed edit survives.
          const latestTs = this.latestCacheTimestamp.get(cacheKey) ?? -1
          if (result.timestamp >= latestTs) {
            this.writeCache(cacheKey, result)
            this.onRevalidated?.(pathAndQuery, result)
          }
          return
        }

        if (!fallbackSet?.has(res.status)) {
          // Genuine server answer (e.g. 403 or 404) — stop retrying.
          return
        }

        retryAfterHeader = res.headers.get("Retry-After")
      } catch {
        // Transport failure — keep retrying with exponential backoff.
        retryAfterHeader = null
      }
    }
  }

  /**
   * Read the cached snapshot for a document `path` WITHOUT hitting the network —
   * the basis for cache-first paint (seed the UI from the last-synced snapshot,
   * then revalidate with a live {@link pull}). Returns the tagged `PullResult`,
   * or null when no cache is configured / there's no entry. Namespacing matches
   * {@link pull}, so the key lines up with whatever `pull` wrote.
   */
  async peekCache(path: string): Promise<PullResult | null> {
    if (!this.cache) return null
    return this.readCache(pullCacheKey(this.applyNamespace(path)))
  }

  /** Read + parse a cached pull snapshot, tagged {@link tagFromCache}. Returns
   *  null on a miss or an unparseable blob (never throws — a corrupt cache entry
   *  must not break a pull, just miss). */
  private async readCache(cacheKey: string): Promise<PullResult | null> {
    try {
      const raw = await this.cache!.get(cacheKey)
      if (!raw) return null
      const parsed = JSON.parse(raw) as CachedPull
      if (!parsed || typeof parsed.hash !== "string") return null
      // Expiry: a snapshot older than the configured max age is a miss. Entries
      // written before this field existed (cachedAt missing) count as age 0 ⇒
      // expired under any TTL, forcing a fresh pull once.
      if (this.cacheMaxAgeMs != null && Date.now() - (parsed.cachedAt ?? 0) > this.cacheMaxAgeMs) {
        return null
      }
      return this.tagFromCache({ data: parsed.data ?? {}, hash: parsed.hash, timestamp: parsed.timestamp ?? 0 })
    } catch {
      return null
    }
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
   * Pass `appendParams` per entry for append-only bounded-tail reads (see {@link batchPullManyAppend}).
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
    if (opts.appendParams && Object.keys(opts.appendParams).length > 0) {
      // Client-side guard: `full` is disallowed in batch (DoS risk). Apply the
      // same `full ⊥ since/limit/last` mutual-exclusion check from pull() too.
      for (const [col, optsArr] of Object.entries(opts.appendParams)) {
        for (const ap of optsArr) {
          if (ap.full) {
            throw new Error(
              `batchPull: appendParams["${col}"] contains full:true — full is not supported in batch pull`,
            )
          }
          // Validate since/last/limit are non-negative integers (floats are rejected
          // server-side; reject client-side for a faster, clearer error).
          if (ap.since != null && (!Number.isInteger(ap.since) || ap.since < 0)) {
            throw new Error(`batchPull: appendParams["${col}"].since must be a non-negative integer`)
          }
          if (ap.last != null && (!Number.isInteger(ap.last) || ap.last < 0)) {
            throw new Error(`batchPull: appendParams["${col}"].last must be a non-negative integer`)
          }
          if (ap.limit != null && (!Number.isInteger(ap.limit) || ap.limit < 0)) {
            throw new Error(`batchPull: appendParams["${col}"].limit must be a non-negative integer`)
          }
        }
      }
      search.set("appendParams", JSON.stringify(opts.appendParams))
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
   * Convenience over {@link batchPull} for reading append-only bounded tails from
   * MANY entries of ONE collection in a single round-trip.
   *
   * Each request in `requests` carries optional `params` (path params) and
   * `options` (append bounds: `since`/`last`/`limit`/`appendField`). An empty
   * `requests` issues no request and returns `[]`.
   *
   * Returns an array aligned to `requests` by index. Each element is either:
   * - the filtered array `T[]` extracted from `entry.data[appendField]`, or
   * - `{ error: string }` if the server returned a per-entry error.
   *
   * The `appendField` used for extraction defaults to `"items"` and can be
   * overridden per request via `options.appendField`.
   *
   * The `appendField` option is client-side only (used for result extraction, not sent to the server).
   * It must match the collection's server-configured append field and defaults to `"items"`.
   *
   * Note: `full: true` is not supported in batch and is rejected client-side
   * before the request is sent.
   */
  async batchPullManyAppend<T = unknown>(
    collection: string,
    requests: { params?: Record<string, string>; options: AppendPullOptions }[],
  ): Promise<(T[] | { error: string })[]> {
    if (requests.length === 0) return []
    const paramsList = requests.map((r) => r.params ?? {})
    // Strip appendField from wire opts — server uses its configured field,
    // not the client-supplied one. We keep it locally for result extraction below.
    const appendParamsList = requests.map(({ options: { appendField: _af, ...wireOpts } }) => wireOpts)
    const res = await this.batchPull([collection], {
      params: { [collection]: paramsList },
      appendParams: { [collection]: appendParamsList },
    })
    const entries = res.collections[collection] ?? []
    return entries.map((entry, i) => {
      if (entry.error) return { error: entry.error }
      const appendField = requests[i]?.options.appendField ?? APPEND_DEFAULT_FIELD
      const data = entry.data as Record<string, unknown> | undefined
      const items = data?.[appendField]
      return Array.isArray(items) ? (items as T[]) : []
    })
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
    const result = (await res.json()) as PushSuccess
    // Write-through: update the pull cache with the pushed data so an offline
    // restart reads the just-written state rather than the pre-push snapshot.
    // The push path is /push/X; the corresponding pull cache key is /pull/X.
    if (this.cache) {
      const pullPath = sendPath.replace("/push/", "/pull/")
      this.writeCache(pullCacheKey(pullPath), { data, hash: result.hash, timestamp: result.timestamp })
    }
    return result
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
   * Append one element to a **public-write** append-only collection with an
   * Ed25519 author proof but **no cap `Authorization` header**.
   *
   * Unlike {@link append}, which always attaches a cap-signed `Authorization`
   * header from the configured `capProvider`, this method signs only the
   * append-author proof (binding the element to the writer's Ed25519 key) and
   * sends the request without authentication headers. This is required for
   * collections with `writeRoles: ["public"]` — the server's cap-scope check
   * would reject a request carrying a cap whose scope does not cover the path.
   *
   * Typical use-case: writing a sealed invitation to another user's
   * public-write inbox collection without needing a cap scoped to the
   * recipient's namespace. The author proof is optional on the server side
   * (`requireAuthorSignature: false` for a public inbox), but signing anyway
   * binds the stored element to the sender's Ed25519 key for verification in
   * the receive path.
   *
   * The element is sent as `{ data, authorPubkey, authorSignature }`.
   *
   * @param path    The push path, e.g. `/push/inbox/{userId}/{shard}`.
   * @param element The JSON element to append.
   * @param signer  The sender's Ed25519 keypair (signs the author proof).
   *
   * @throws {AppendHttpError} on a non-2xx response.
   */
  async appendAnonymous(
    path: string,
    element: Record<string, unknown>,
    signer: { edPubHex: string; edPrivHex: string },
  ): Promise<void> {
    const sendPath = this.applyNamespace(path)
    const documentKey = stripPushPrefix(path)
    const { authorPubkey, authorSignature } = signAppendAuthor(
      documentKey,
      element,
      signer.edPubHex,
      signer.edPrivHex,
    )
    const body = JSON.stringify({
      [DATA_FIELD]: element,
      [AUTHOR_PUBKEY_FIELD]: authorPubkey,
      [AUTHOR_SIGNATURE_FIELD]: authorSignature,
    })
    const res = await this.fetch(`${this.baseUrl}${sendPath}`, {
      method: "POST",
      headers: {
        [HEADER_CONTENT_TYPE]: "application/json",
        [HEADER_ACCEPT]: "application/json",
      },
      body,
    })
    if (!res.ok) {
      const detail = await res.text().catch(() => "")
      throw new AppendHttpError(
        res.status,
        `anonymous append failed: HTTP ${res.status} ${detail}`.trim(),
      )
    }
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

  /**
   * Push an Apache Parquet file to a Parquet collection.
   *
   * Thin wrapper over {@link pushBlob} that fixes `Content-Type` to
   * `application/vnd.apache.parquet` so the S3 object is tagged correctly
   * for DuckDB and CDN consumption.
   *
   * @example
   * ```ts
   * const parquetBytes = await generateParquet(rows)
   * const result = await client.pushParquet("/push/analytics/alice/q1.parquet", parquetBytes)
   * console.log("stored hash:", result.hash)
   * ```
   */
  async pushParquet(
    path: string,
    data: ArrayBuffer | Uint8Array | Blob,
  ): Promise<BlobPushResult> {
    return this.pushBlob(path, data, PARQUET_MIME_TYPE_VALUE)
  }

  /**
   * Pull an Apache Parquet file from a Parquet collection.
   *
   * Thin wrapper over {@link pullBlob} for API symmetry with
   * {@link pushParquet}.
   *
   * @example
   * ```ts
   * const result = await client.pullParquet("/pull/analytics/alice/q1.parquet")
   * // result.data        → ArrayBuffer
   * // result.contentType → "application/vnd.apache.parquet"
   * ```
   */
  async pullParquet(path: string): Promise<BlobPullResult> {
    const result = await this.pullBlob(path)
    if (!PARQUET_MIME_TYPES_VALUE.includes(result.contentType as any)) {
      throw new StarfishHttpError(
        415,
        `Expected a Parquet content-type, got: ${result.contentType}`,
      )
    }
    return result
  }
}
