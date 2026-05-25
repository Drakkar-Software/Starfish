import type { Alg, CapCert } from "@drakkar.software/starfish-protocol"

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
   *
   * `presenterAlg` is the crypto suite of `devEdPrivHex` (the key that signs
   * the request). It matters only for `audience` caps, where the presenter is
   * an arbitrary redeemer whose suite is unrelated to the cap's `issAlg`; the
   * client sends it as `X-Starfish-Alg`. For device/member caps the subject's
   * suite is taken authoritatively from the verified cert, so this is ignored.
   * Defaults to `"ed25519"` when omitted.
   */
  getCap(): Promise<{
    cap: CapCert
    devEdPrivHex: string
    pubHex?: string
    presenterAlg?: Alg
  }>
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
