import type { CapCert } from "@drakkar.software/starfish-protocol"

/** Push conflict error (HTTP 409). */
export class ConflictError extends Error {
  constructor() {
    super("hash_mismatch")
    this.name = "ConflictError"
  }
}

/** HTTP error from the Starfish server. */
export class StarfishHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string
  ) {
    super(`HTTP ${status}: ${body}`)
    this.name = "StarfishHttpError"
  }
}

/**
 * v3.0 cap-cert provider for `StarfishClient`. Returns the device's cap-cert and
 * the matching Ed25519 private key (hex). The client calls `getCap()` once per
 * outgoing request; implementations are expected to cache so this is cheap.
 *
 * When set, the client signs every outgoing request: each call carries
 * `Authorization: Cap <base64(stableStringify(cap))>` plus `X-Starfish-Sig`,
 * `X-Starfish-Ts`, `X-Starfish-Nonce`.
 */
export interface StarfishCapProvider {
  /**
   * Returns the device's cap-cert and its Ed25519 private key (hex).
   * Implementations are expected to cache; the client may call this once per
   * authenticated request.
   *
   * For an `audience` (public-link) cap, which binds no single subject, also
   * return `pubHex` — the redeemer's own Ed25519 pubkey matching `devEdPrivHex`.
   * The client then sends it as `X-Starfish-Pub` so the server can verify the
   * request signature against it and check the cap's `aud` allow-list. Omit
   * `pubHex` for device/member caps (the server uses `cap.sub`).
   */
  getCap(): Promise<{
    cap: CapCert
    devEdPrivHex: string
    pubHex?: string
  }>
}

/**
 * A minimal async key-value store the client uses as a read-through cache for
 * {@link StarfishClient.pull} (offline-first reads). Host-provided so the SDK
 * stays storage-agnostic — back it by `localStorage`, `AsyncStorage`, a file,
 * etc. Shaped like a subset of zustand's `StateStorage` so an existing adapter
 * fits.
 *
 * IMPORTANT — what gets stored: the client caches the RAW server response only
 * (`data`/`hash`/`timestamp`). For E2E (`delegated`) collections that payload is
 * the SEALED ciphertext the server holds — never the decrypted form — so this
 * cache is ciphertext-at-rest by construction. Decryption always happens in
 * memory on read (see {@link SyncManager}). Public/plaintext collections cache
 * their plaintext, exactly as the server stores it.
 */
export interface PullCache {
  /** Return the previously-stored string for `key`, or null if absent. Must not throw. */
  get(key: string): Promise<string | null>
  /** Store `value` under `key`. Must not throw (failures are swallowed by the client). */
  set(key: string, value: string): Promise<void>
}

/** Options for creating a StarfishClient. */
export interface StarfishClientOptions {
  /** Base URL of the Starfish server (e.g. "https://api.example.com/v1"). */
  baseUrl: string
  /**
   * Optional namespace for a namespace-mounted server. When set, every request
   * path `/{action}/…` is rewritten to `/v1/{namespace}/{action}/…` for BOTH the
   * URL the client hits AND the canonical path it signs, so the signature the
   * server reconstructs from the namespaced URL verifies (no rewrite layer
   * needed). Mirrors the Python client's `namespace` parameter.
   *
   * Crucially this also rewrites the paths that namespace-unaware SDK helpers
   * build internally (e.g. `starfish-keyring`'s `addCollectionRecipient`, blob
   * uploads), so consumers no longer hand-prefix paths or wrap the client to
   * reach a namespaced deployment. Leave unset (default) for a root-mounted
   * server — paths pass through unchanged, byte-identical to before.
   *
   * Pass the bare namespace name (e.g. `"octochat"`); `baseUrl` then carries only
   * the origin (and any reverse-proxy mount the proxy strips), not the `/v1`
   * version segment. Must match `[A-Za-z0-9_-]+` and not be a reserved route name
   * (`pull`, `push`, `health`, `batch`).
   */
  namespace?: string
  /**
   * Cap-cert provider. When set, requests are signed with Ed25519 and carry
   * `Authorization: Cap <…>`. Omit for unauthenticated public-read collections.
   */
  capProvider?: StarfishCapProvider
  /** Optional fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch
  /**
   * Optional read-through cache for {@link StarfishClient.pull} — the basis for
   * offline-first reads. When set, every successful non-append pull is written
   * through to the cache (keyed by document path), and a pull that fails because
   * the TRANSPORT is unreachable (offline / DNS / timeout — `fetch` rejects)
   * falls back to the cached response, tagged so callers can tell it's stale.
   *
   * A real HTTP error (404/403/5xx) is a genuine server answer and always
   * propagates — the cache is NOT consulted — so "no document yet" and
   * "access denied" keep their meaning. Caches ciphertext for E2E collections
   * (the server only ever holds sealed payloads); never decrypted data.
   */
  cache?: PullCache
  /**
   * Optional max age (ms) for {@link cache} entries. An entry older than this is
   * treated as a cache MISS on every read — both cache-first paint and the
   * offline fallback — so a stale-beyond-policy snapshot is never served (the
   * pull then goes to the network, or rethrows the transport error offline).
   * Each cached snapshot records its write time; expiry is `now - cachedAt >
   * cacheMaxAgeMs`. Omit (default) for entries that never expire — recommended
   * for an offline-first app where any last-synced data beats none.
   */
  cacheMaxAgeMs?: number
  /**
   * Optional list of client-side plugins. The list is stored on the client
   * instance but does not fire any hooks yet — the contract is plumbed so
   * extension packages (`starfish-identities`, `starfish-keyring`,
   * `starfish-sharing`, …) can register against it later without a breaking
   * API change.
   *
   * The current set of hooks is purposely empty; extensions that need to
   * react to mint events or transport actions today can wrap the client
   * directly. Future hook additions will be additive.
   */
  plugins?: ClientPlugin[]
}

/**
 * Client-side plugin contract.
 *
 * A placeholder shape: the interface intentionally has no required hooks
 * yet; extensions declare a plugin object with `name` and opt into
 * specific lifecycle hooks once those exist. Apps wire plugins via
 * `new StarfishClient({ plugins: [...] })`.
 */
export interface ClientPlugin {
  /** Human-readable name. Used in error messages and audit output. */
  name: string
  /**
   * Reserved for future hook fields. Plugins typically declare only
   * `name`. Hook additions are additive — extensions implementing a
   * future hook will populate the relevant optional property without
   * affecting existing zero-hook plugins.
   */
}

/** Conflict resolver: given local and remote data, return merged result. */
export type ConflictResolver = (
  local: Record<string, unknown>,
  remote: Record<string, unknown>
) => Record<string, unknown>
