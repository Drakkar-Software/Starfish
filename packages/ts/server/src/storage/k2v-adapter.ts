/**
 * `KVAdapter` backed by Garage K2V (https://garagehq.deuxfleurs.fr/documentation/reference-manual/k2v/).
 *
 * This shares rate-limit counters and nonce flags across server instances. K2V is a
 * CRDT-style store with NO compare-and-set and NO atomic increment: concurrent writes to
 * one key become "siblings" that the reader merges, with optimistic concurrency via an
 * `X-Garage-Causality-Token`. K2V also has no native key expiry. This adapter therefore:
 *
 *  - embeds an `exp` (ms) in every value and treats expired-on-read entries as absent
 *    (logically expired keys linger in K2V until overwritten or externally pruned — there
 *    is no TTL; size/scrub your bucket accordingly);
 *  - on `increment`, reads all live siblings, **sums** their counts, and writes back the
 *    merged total superseding the read causality token. Under concurrent increments the
 *    siblings can briefly **overcount** (a stricter, fail-closed limit) — never undercount;
 *  - on `recordIfAbsent`, does a best-effort read-then-write. Without CAS, two *concurrent*
 *    requests with the *same* key can both be accepted (a narrow replay window). The `group`
 *    fail-closed cap is **ignored** (K2V can't cheaply count a group). Use a CAS-capable
 *    store if you need exact distributed replay protection.
 *
 * The HTTP/auth boundary is an injectable {@link K2VTransport}, so the protocol logic here
 * is testable with a mock and you can supply auth (AWS SigV4, a proxy, etc.) however you like.
 */
import type { KVAdapter } from "./kv-adapter.js"

/** Result of a K2V ReadItem: the live + tombstone sibling values and the causality token. */
export interface K2VReadResult {
  /** Sibling values (UTF-8). Tombstones are omitted. Empty when the key is absent. */
  values: string[]
  /** Opaque causality token to pass to a superseding insert/delete; null when absent. */
  causality: string | null
}

/** The HTTP/auth boundary for {@link createK2VAdapter}. Implement against Garage's K2V API. */
export interface K2VTransport {
  /** ReadItem `(partitionKey, sortKey)` → sibling values + causality token. */
  read(partitionKey: string, sortKey: string): Promise<K2VReadResult>
  /** InsertItem `(partitionKey, sortKey, value)`, superseding `causality` when provided. */
  insert(partitionKey: string, sortKey: string, value: string, causality: string | null): Promise<void>
}

/** Options for {@link createK2VAdapter}. */
export interface K2VAdapterOptions {
  /** The K2V HTTP/auth transport. */
  transport: K2VTransport
  /** K2V partition key under which all keys are stored (sort key = the app key).
   *  Default `"starfish-kv"`. */
  partitionKey?: string
  /** Clock (ms); defaults to `Date.now`. */
  now?: () => number
}

interface StoredValue {
  exp: number
  n?: number
}

function parseValue(raw: string): StoredValue | null {
  try {
    const v = JSON.parse(raw) as StoredValue
    return typeof v?.exp === "number" ? v : null
  } catch {
    return null
  }
}

/**
 * Build a {@link KVAdapter} over Garage K2V. See the file header for the consistency
 * caveats (overcount under contention; best-effort replay protection without CAS).
 */
export function createK2VAdapter(opts: K2VAdapterOptions): KVAdapter {
  const transport = opts.transport
  const pk = opts.partitionKey ?? "starfish-kv"
  const now = opts.now ?? Date.now

  return {
    async increment(key, ttlMs) {
      const { values, causality } = await transport.read(pk, key)
      const t = now()
      let sum = 0
      for (const raw of values) {
        const v = parseValue(raw)
        if (v && v.exp > t) sum += v.n ?? 0
      }
      const next = sum + 1
      await transport.insert(pk, key, JSON.stringify({ exp: t + ttlMs, n: next }), causality)
      return next
    },

    async recordIfAbsent(key, ttlMs, _group) {
      const { values, causality } = await transport.read(pk, key)
      const t = now()
      const live = values.some((raw) => {
        const v = parseValue(raw)
        return v != null && v.exp > t
      })
      if (live) return false
      await transport.insert(pk, key, JSON.stringify({ exp: t + ttlMs }), causality)
      return true
    },
  }
}

// --- Default fetch-based transport ---

/** Hook to attach auth (e.g. AWS SigV4) to an outgoing K2V request before it is sent. */
export type K2VRequestSigner = (req: {
  method: string
  url: string
  headers: Record<string, string>
  body?: string
}) => Record<string, string> | Promise<Record<string, string>>

/** Options for {@link createFetchK2VTransport}. */
export interface FetchK2VTransportOptions {
  /** Base URL of the Garage K2V endpoint, e.g. `"https://garage.example.com"`. */
  endpoint: string
  /** Bucket name. */
  bucket: string
  /** `fetch` implementation. Defaults to the global `fetch`. */
  fetch?: typeof fetch
  /** Optional hook to add auth headers (SigV4, bearer, etc.). When omitted, requests are
   *  sent unsigned — only appropriate for a trusted network or an auth-injecting proxy. */
  signRequest?: K2VRequestSigner
}

/**
 * A {@link K2VTransport} over HTTP using `fetch`, speaking the Garage K2V API: ReadItem
 * with `Accept: application/json` (returns a base64 sibling array + `X-Garage-Causality-Token`),
 * and InsertItem via `PUT ?sort_key=` carrying the causality token to supersede.
 */
export function createFetchK2VTransport(opts: FetchK2VTransportOptions): K2VTransport {
  const doFetch = opts.fetch ?? fetch
  const base = opts.endpoint.replace(/\/$/, "")
  const enc = (s: string): string => encodeURIComponent(s)

  async function signed(method: string, url: string, body?: string): Promise<Record<string, string>> {
    const headers: Record<string, string> = {}
    if (body !== undefined) headers["Content-Type"] = "application/octet-stream"
    if (opts.signRequest) return { ...headers, ...(await opts.signRequest({ method, url, headers, body })) }
    return headers
  }

  return {
    async read(partitionKey, sortKey) {
      const url = `${base}/${enc(opts.bucket)}/${enc(partitionKey)}?sort_key=${enc(sortKey)}`
      const headers = await signed("GET", url)
      headers["Accept"] = "application/json"
      const res = await doFetch(url, { method: "GET", headers })
      if (res.status === 404) return { values: [], causality: null }
      if (!res.ok) throw new Error(`K2V read failed: ${res.status}`)
      const causality = res.headers.get("x-garage-causality-token")
      // ReadItem with Accept: application/json returns a JSON array of base64 strings;
      // a `null` entry is a tombstone (concurrent delete) and is skipped.
      const arr = (await res.json()) as (string | null)[]
      const values = arr
        .filter((v): v is string => v != null)
        .map((b64) => Buffer.from(b64, "base64").toString("utf-8"))
      return { values, causality }
    },

    async insert(partitionKey, sortKey, value, causality) {
      const url = `${base}/${enc(opts.bucket)}/${enc(partitionKey)}?sort_key=${enc(sortKey)}`
      const headers = await signed("PUT", url, value)
      if (causality) headers["X-Garage-Causality-Token"] = causality
      const res = await doFetch(url, { method: "PUT", headers, body: value })
      if (!res.ok) throw new Error(`K2V insert failed: ${res.status}`)
    },
  }
}
