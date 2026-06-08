/**
 * Authenticated SSE proxy router factory.
 *
 * Generalizes the per-app `/events` SSE proxy (an app gating an upstream
 * change-event firehose behind cap-cert auth + per-resource authorization) into
 * a framework primitive. Apps supply the policy callbacks; this module owns the
 * shared mechanics:
 *
 *   - authenticate the (bodyless) subscribe request → identity | null (401),
 *   - parse a bounded `?<candidatesParam>=a,b,c` candidate list (400 on
 *     overflow),
 *   - per-candidate gate: open-gate a public candidate (`publicPredicate`) or
 *     call `authorize(identity, candidate)`; reject any candidate whose id does
 *     not fullmatch `idPattern` on EITHER branch,
 *   - cap the authorized set at `maxTopics` (silent truncation beyond),
 *   - map authorized candidates through `topicMapper` to upstream topics,
 *   - FIREHOSE-PREVENTION INVARIANT: the upstream URL always carries at least
 *     one `topic=`; an empty authorized set substitutes the sentinel
 *     `__none__`,
 *   - proxy the upstream SSE stream, propagating client disconnect.
 *
 * No app-specific (octobot/octochat/…) names appear here — the upstream topic
 * transform, the authorization policy, and the public open-gate are all caller
 * supplied. Parity with `starfish_server.events_proxy` (Python).
 */

import { Hono } from "hono"
import type { Context } from "hono"

/**
 * Shared default id charset (matches the per-app product/space id rule). The
 * pattern is anchored so `.test()` behaves like a Python `fullmatch`: a trailing
 * newline cannot slip through and perturb the upstream topic reconstruction.
 */
export const DEFAULT_SAFE_ID = /^[a-zA-Z0-9_-]+$/

/**
 * Sentinel substituted when nothing is authorized, so the upstream URL always
 * carries at least one `topic=` (a topic-less upstream subscribe is a firehose).
 */
const NONE_SENTINEL = "__none__"

/** Options for {@link createEventsProxyRouter}. */
export interface EventsProxyOptions {
  /**
   * Resolves the caller's identity from the (bodyless) request, or `null` →
   * 401. Wrap {@link authenticateMetaRequest} with the route's pre-bound
   * caches/validators.
   */
  authenticate: (c: Context) => Promise<string | null>
  /** Query-param name carrying the comma-separated candidate ids. */
  candidatesParam: string
  /**
   * `async (identity, candidate) -> boolean` — true iff the caller may
   * subscribe to `candidate`. Called once per non-public candidate.
   */
  authorize: (identity: string, candidate: string) => Promise<boolean>
  /**
   * `candidate -> string[]` — the upstream topic transform for ONE authorized
   * candidate (the caller owns sanitization / namespacing). May return multiple
   * upstream topics per candidate.
   */
  topicMapper: (candidate: string) => string[]
  /** Upstream SSE endpoint; the `topic=` query is appended. */
  upstreamUrl: string
  /** Pre-auth cap on parsed candidate ids; 400 if exceeded. */
  maxCandidates: number
  /** Cap on AUTHORIZED candidates; beyond it, extras are silently truncated. */
  maxTopics: number
  /**
   * Optional `candidate -> boolean` — when true the candidate is open-gated (no
   * `authorize` call), still id-validated and still counted against `maxTopics`.
   */
  publicPredicate?: (candidate: string) => boolean
  /**
   * Optional cap applied ONLY to `publicPredicate` matches. When set, public
   * candidates beyond it are silently skipped — without truncating the loop, so
   * private candidates later in the list still authorize — while `maxTopics`
   * still bounds the total. Omit to keep a single `maxTopics` cap. Lets a host
   * cap a cheap-to-spoof public fan-out tighter than its private subscriptions.
   */
  maxPublicTopics?: number
  /**
   * Regex; every candidate id must match it on BOTH the public and the
   * authorized branch. Defaults to {@link DEFAULT_SAFE_ID}.
   */
  idPattern?: RegExp
}

/**
 * Build a Hono router exposing a single authenticated SSE `GET /events` proxy.
 * See {@link EventsProxyOptions} for the policy callbacks.
 */
export function createEventsProxyRouter(opts: EventsProxyOptions): Hono {
  const idPattern = opts.idPattern ?? DEFAULT_SAFE_ID
  const app = new Hono()

  app.get("/events", async (c) => {
    // 1. Authenticate (cap-cert + request signature, bodyless).
    const identity = await opts.authenticate(c)
    if (!identity) return c.json({ error: "unauthorized" }, 401)

    // 2. Candidate ids from ?<candidatesParam>=a,b,c.
    const raw = c.req.query(opts.candidatesParam) ?? ""
    const candidates = raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
    if (candidates.length > opts.maxCandidates) {
      // Cap pre-auth so an attacker can't trigger N authorize calls per request.
      return c.json({ error: "too many candidates" }, 400)
    }

    // 3. Per-candidate gate. Public candidates are open-gated; the rest go
    //    through authorize(). Every id is charset-validated on BOTH branches (a
    //    bad id is silently dropped, never proxied).
    const authorized: string[] = []
    let publicCount = 0
    let truncated = false
    for (const candidate of candidates) {
      if (authorized.length >= opts.maxTopics) {
        truncated = true
        break
      }
      if (opts.publicPredicate && opts.publicPredicate(candidate)) {
        if (!idPattern.test(candidate)) continue
        // Optional public-only cap: bound the (cheap-to-spoof) public fan-out
        // WITHOUT truncating the loop — skip this public candidate but keep
        // processing, so private candidates later in the list still authorize.
        // `maxTopics` still bounds the total.
        if (opts.maxPublicTopics !== undefined && publicCount >= opts.maxPublicTopics) {
          truncated = true
          continue
        }
        authorized.push(candidate)
        publicCount++
        continue
      }
      if (!idPattern.test(candidate)) continue
      if (await opts.authorize(identity, candidate)) authorized.push(candidate)
    }
    if (truncated) {
      // eslint-disable-next-line no-console
      console.warn(
        `events-proxy: topic cap (${opts.maxTopics}) reached for ${identity}; ` +
          `extra candidates won't live-update until reconnect.`,
      )
    }

    // 4. Map authorized candidates → upstream topics (caller's transform).
    const topics: string[] = []
    for (const candidate of authorized) topics.push(...opts.topicMapper(candidate))

    // 5. Firehose-prevention invariant: never subscribe topic-less upstream.
    const safeTopics = topics.length > 0 ? topics : [NONE_SENTINEL]

    // 6. Proxy the upstream SSE stream, propagating client disconnect.
    const qs = safeTopics.map((t) => "topic=" + encodeURIComponent(t)).join("&")
    const sep = opts.upstreamUrl.includes("?") ? "&" : "?"
    const fullUrl = `${opts.upstreamUrl}${sep}${qs}`

    const upstream = await fetch(fullUrl, {
      headers: { Accept: "text/event-stream" },
      // Propagate client disconnect: when the client aborts, abort upstream.
      signal: c.req.raw.signal,
    })
    if (!upstream.ok || upstream.body === null) {
      return c.body(null, 502)
    }

    c.header("Content-Type", "text/event-stream")
    c.header("Cache-Control", "no-cache")
    c.header("Connection", "keep-alive")
    return c.body(upstream.body)
  })

  return app
}
