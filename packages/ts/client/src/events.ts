/**
 * Generic SSE live-change transport for Starfish `/events` streams.
 *
 * Exported via `@drakkar.software/starfish-client/events` so apps that don't
 * use live sync can exclude this module from their bundle. The three exports
 * are deliberately domain-free — app-specific parsing is injected via a
 * callback so this module can be used with any Starfish server layout:
 *
 * - {@link parseSseFrames} — WHATWG-compliant incremental SSE frame parser.
 *   Pure function, no I/O.
 * - {@link buildSignedEventsUrl} — builds the fetch URL and the stripped
 *   signed path, honouring the convention that the signature covers the path
 *   AFTER any reverse-proxy mount prefix is removed.
 * - {@link subscribeChanges} — opens an auto-reconnecting SSE subscription with
 *   capped exponential backoff. Returns an unsubscribe function.
 *
 * @module starfish-client/events
 */

// ── parseSseFrames ────────────────────────────────────────────────────────────

/**
 * Incrementally parse SSE frames from a raw text chunk (WHATWG SSE spec §10.1).
 *
 * Call on each `Uint8Array` chunk decoded from the response body stream. Pass
 * the `carry` returned by the previous call as the next call's `carry` argument
 * (start with `""`). When the stream ends, any non-empty `carry` is an
 * incomplete final frame and can be discarded.
 *
 * Only `data:` lines are extracted. `id:`, `event:`, `retry:`, and comment (`:`)
 * lines are intentionally skipped — multi-line `data:` payloads are
 * newline-joined per spec.
 *
 * @param chunk  The newly received text (already decoded from UTF-8).
 * @param carry  Leftover incomplete-frame text from the previous call.
 * @returns      Completed `data` payloads and the new carry for the next call.
 */
export function parseSseFrames(
  chunk: string,
  carry: string,
): { events: string[]; carry: string } {
  // Normalise \r\n and \r → \n per spec.
  const text = (carry + chunk).replace(/\r\n/g, "\n").replace(/\r/g, "\n")
  // Frames are separated by blank lines.
  const parts = text.split("\n\n")
  const events: string[] = []
  for (let i = 0; i < parts.length - 1; i++) {
    const dataLines: string[] = []
    for (const line of parts[i]!.split("\n")) {
      if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart())
      // id:, event:, retry:, and comment (:) lines are intentionally ignored.
    }
    if (dataLines.length > 0) events.push(dataLines.join("\n"))
  }
  // The last part may be an incomplete frame — carry it to the next call.
  return { events, carry: parts[parts.length - 1]! }
}

// ── buildSignedEventsUrl ──────────────────────────────────────────────────────

/**
 * Build the fetch URL and the signed `pathAndQuery` for an SSE request.
 *
 * Two invariants enforced:
 *
 * 1. The `mountBase` prefix (e.g. the `/sync` part of `https://api.example.com/sync`)
 *    is stripped from the **signed path** so the signature matches what the origin
 *    server verifies after a reverse proxy strips the mount prefix — exactly as
 *    `StarfishClient.pull` signs `applyNamespace(path)` without the `baseUrl`
 *    origin. Pass `mountBase` as your Starfish `baseUrl`.
 *
 * 2. Query-parameter values are percent-encoded by `URLSearchParams` so a
 *    normalising CDN (e.g. Cloudflare) cannot re-encode a literal comma and
 *    invalidate the signature.
 *
 * @param eventsUrl   Fully-qualified URL of the SSE endpoint
 *                    (e.g. `"https://api.example.com/sync/events"`).
 * @param params      Optional additional query parameters (merged with any
 *                    existing params on `eventsUrl`).
 * @param mountBase   Optional base URL whose pathname is stripped from the
 *                    signed path (your Starfish `baseUrl`).
 *
 * @returns `{ url, pathAndQuery }` — `url` is for the `fetch` call; `pathAndQuery`
 *          is the path that must be signed by `authHeaders`.
 */
export function buildSignedEventsUrl(
  eventsUrl: string,
  params?: Record<string, string>,
  mountBase?: string,
): { url: string; pathAndQuery: string } {
  const u = new URL(eventsUrl)

  if (params) {
    for (const [k, v] of Object.entries(params)) {
      u.searchParams.set(k, v)
    }
  }

  let basePath = ""
  if (mountBase) {
    try {
      basePath = new URL(mountBase).pathname.replace(/\/+$/, "")
    } catch {
      // Relative base — no prefix to strip.
    }
  }
  const signedPath =
    basePath && u.pathname.startsWith(basePath)
      ? u.pathname.slice(basePath.length)
      : u.pathname

  return { url: u.toString(), pathAndQuery: signedPath + u.search }
}

// ── subscribeChanges ──────────────────────────────────────────────────────────

/** Options for {@link subscribeChanges}. */
export interface SubscribeChangesOptions<T> {
  /**
   * Fully-qualified SSE endpoint URL.
   * May be a factory function so a fresh URL (with updated params) is built
   * on every reconnect attempt — useful when query params carry a fresh auth
   * token or updated filter set.
   */
  url: string | (() => string)
  /**
   * The path string that is passed to `authHeaders`. Must be the path the
   * server verifies the signature over — typically the pathname + search AFTER
   * the mount prefix is stripped. If omitted, the full pathname + search of
   * `url` is used as-is.
   *
   * May also be a factory function (called once per connect attempt, in sync
   * with the `url` factory if both are functions).
   */
  pathAndQuery?: string | (() => string)
  /**
   * Async function that returns auth headers for a given HTTP method and
   * `pathAndQuery`. Typically wraps the StarfishClient's `buildAuthHeaders`
   * or equivalent. Called on every reconnect so fresh tokens are obtained
   * after a long disconnect.
   */
  authHeaders: (method: string, pathAndQuery: string) => Promise<Record<string, string>>
  /**
   * Parse one SSE `data:` payload and return the domain change object, or
   * `null` to skip the frame. This is the ONLY app-specific injection point —
   * all transport logic stays in this module.
   */
  parse: (data: string) => T | null
  /** Fired for each successfully parsed change event. */
  onChange: (change: T) => void
  /**
   * Status callback:
   * - `true` when the first byte of a new stream arrives (connected).
   * - `false` when the stream closes, an error is thrown, or unsubscribe is called.
   */
  onStatus?: (connected: boolean) => void
  /**
   * Minimum reconnect delay in ms. Reset to this value after a successful
   * connect (at least one byte received). Defaults to `1000`.
   */
  minReconnectMs?: number
  /**
   * Maximum reconnect delay in ms — exponential backoff caps here.
   * Defaults to `30000`.
   */
  maxReconnectMs?: number
}

/**
 * Open a single auto-reconnecting SSE subscription.
 *
 * - Obtains fresh auth headers on every reconnect attempt so long-running
 *   sessions survive cap rotation.
 * - Uses capped exponential backoff: resets to `minReconnectMs` after a
 *   successful connect, doubles up to `maxReconnectMs` on failure.
 * - Streams are read via the WHATWG `ReadableStream` API (available in all
 *   modern environments including React Native / Hermes with polyfill).
 *
 * @returns Unsubscribe function. Call it to abort the stream immediately and
 *          stop all reconnect attempts.
 *
 * @example
 * ```ts
 * import { buildSignedEventsUrl, subscribeChanges } from "@drakkar.software/starfish-client/events"
 *
 * const unsub = subscribeChanges({
 *   url: () => buildSignedEventsUrl(serverUrl + "/events", { ns: namespace }).url,
 *   pathAndQuery: () => buildSignedEventsUrl(serverUrl + "/events", { ns: namespace }).pathAndQuery,
 *   authHeaders: (method, pq) => client.buildAuthHeadersForPath(method, pq),
 *   parse: (data) => {
 *     try { return JSON.parse(data) } catch { return null }
 *   },
 *   onChange: (change) => console.log("change", change),
 *   onStatus: (connected) => setConnected(connected),
 * })
 *
 * // Later: unsub()
 * ```
 */
export function subscribeChanges<T>(opts: SubscribeChangesOptions<T>): () => void {
  const {
    url: urlOrFactory,
    pathAndQuery: pqOrFactory,
    authHeaders,
    parse,
    onChange,
    onStatus,
    minReconnectMs = 1_000,
    maxReconnectMs = 30_000,
  } = opts

  let closed = false
  let backoff = minReconnectMs
  const controller = new AbortController()

  void (async () => {
    while (!closed) {
      const url = typeof urlOrFactory === "function" ? urlOrFactory() : urlOrFactory

      let pathAndQuery: string
      if (typeof pqOrFactory === "function") {
        pathAndQuery = pqOrFactory()
      } else if (pqOrFactory !== undefined) {
        pathAndQuery = pqOrFactory
      } else {
        // Default: pathname + search from the resolved URL.
        try {
          const u = new URL(url)
          pathAndQuery = u.pathname + u.search
        } catch {
          pathAndQuery = url
        }
      }

      let extraHeaders: Record<string, string>
      try {
        extraHeaders = await authHeaders("GET", pathAndQuery)
      } catch {
        // Signing failure — session likely gone. Stop reconnecting.
        break
      }
      if (closed) break

      let connected = false
      try {
        const res = await fetch(url, {
          headers: { Accept: "text/event-stream", ...extraHeaders },
          signal: controller.signal,
        })
        if (!res.ok || !res.body) throw new Error(`SSE ${res.status}`)

        onStatus?.(true)
        connected = true
        backoff = minReconnectMs // Reset backoff on successful connect.

        const reader = (res.body as ReadableStream<Uint8Array>).getReader()
        const decoder = new TextDecoder()
        let carry = ""

        try {
          while (!closed) {
            const { value, done } = await reader.read()
            if (done) break
            const chunk = decoder.decode(value, { stream: true })
            const { events, carry: next } = parseSseFrames(chunk, carry)
            carry = next
            for (const data of events) {
              const change = parse(data)
              if (change !== null) onChange(change)
            }
          }
        } finally {
          reader.releaseLock()
        }
      } catch {
        // Network error, abort, or non-ok response — fall through to reconnect.
      }

      if (closed || controller.signal.aborted) break

      if (connected) onStatus?.(false)

      // Backoff before the next attempt (doubles on each failure, capped at max).
      await new Promise<void>((resolve) => setTimeout(resolve, backoff))
      if (!connected) backoff = Math.min(backoff * 2, maxReconnectMs)
    }
  })()

  return () => {
    closed = true
    controller.abort()
    onStatus?.(false)
  }
}
