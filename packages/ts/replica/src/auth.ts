/**
 * Replica-request signing client.
 *
 * A replica node pulls/pushes against a primary Starfish server with
 * authenticated, per-request-signed HTTP calls. {@link createReplicaAuth}
 * builds a signing `fetch` wrapper an app injects into the
 * {@link ReplicaManager} via its `fetchFn` option:
 *
 * ```ts
 * const auth = await createReplicaAuth({ passphrase: "..." })
 * const manager = new ReplicaManager(store, collections, { fetchFn: auth.fetch })
 * ```
 *
 * It is pure Starfish plumbing — no product/app logic. Per request it:
 *
 * 1. signs the canonical request bytes with `signRequest` and attaches the
 *    `X-Starfish-Sig`/`-Ts`/`-Nonce` headers, and
 * 2. attaches an `Authorization: Cap <base64(stableStringify(cap))>` header
 *    built from a self-signed device cap-cert.
 *
 * The cap-cert has a finite TTL (`mintDeviceCap` defaults to 30 days). A
 * long-uptime replica would otherwise 401-storm once the cap expires, so the
 * cap is transparently re-minted when it nears expiry (see `refreshMarginSec`).
 * The signing key and the derived userId never change across a refresh, so the
 * identity (and any role the primary grants it) is preserved.
 */

import {
  signRequest,
  stableStringify,
  getBase64,
  HEADER_AUTHORIZATION,
  HEADER_SIG,
  HEADER_TS,
  HEADER_NONCE,
  type SignableMethod,
  type CapCert,
} from "@drakkar.software/starfish-protocol"
import {
  bootstrapRootIdentity,
  mintDeviceCap,
  scopes,
  type DeviceCredentials,
  type ScopePreset,
} from "@drakkar.software/starfish-identities"

/** Re-mint when the current cap has fewer than this many seconds until exp. */
const DEFAULT_REFRESH_MARGIN_SEC = 24 * 3600

/** Options for {@link createReplicaAuth}. Supply exactly one of `passphrase`/`credentials`. */
export interface ReplicaAuthOptions {
  /** Passphrase to bootstrap the root identity from. Mutually exclusive with `credentials`. */
  passphrase?: string
  /** A pre-bootstrapped `DeviceCredentials`. Mutually exclusive with `passphrase`. */
  credentials?: DeviceCredentials
  /**
   * Cap scope to (re-)mint with. Defaults to `scopes.rootAll()` (read/list/write
   * on every path + collection) — the access a replica needs for pull/push.
   */
  scope?: ScopePreset
  /** Re-mint the cap when fewer than this many seconds remain until exp. Default: one day. */
  refreshMarginSec?: number
  /** Injectable `() => number` returning current Unix seconds. Defaults to `Date.now()/1000`. Used by tests. */
  clock?: () => number
  /** Underlying fetch to delegate to after signing. Defaults to `globalThis.fetch`. */
  fetchFn?: typeof fetch
}

/** A signing `fetch` plus the derived identity. */
export interface ReplicaAuth {
  /**
   * A `typeof fetch` that signs each request (cap header + signature headers)
   * before delegating to the underlying fetch. Hand this to
   * `new ReplicaManager(store, cols, { fetchFn: auth.fetch })`.
   */
  fetch: typeof fetch
  /** The derived root userId (`sha256(rootEdPub)[0:32]`) — cross-check against a configured value. */
  userId: string
}

/**
 * Build a {@link ReplicaAuth} — a signing `fetch` wrapper for replica pull/push.
 *
 * Bootstraps (or accepts a pre-bootstrapped) device identity, caches a
 * self-signed device cap-cert, and signs every outgoing request. The cap is
 * transparently re-minted as it nears expiry.
 */
export async function createReplicaAuth(
  opts: ReplicaAuthOptions,
): Promise<ReplicaAuth> {
  if ((opts.passphrase == null) === (opts.credentials == null)) {
    throw new Error(
      "createReplicaAuth requires exactly one of 'passphrase' or 'credentials'",
    )
  }
  const creds: DeviceCredentials =
    opts.credentials ?? (await bootstrapRootIdentity(opts.passphrase!))

  // Keep the bootstrap outputs so re-minting on expiry needs no key derivation.
  const edPriv = creds.device.edPriv
  const edPub = creds.device.edPub
  const kemPub = creds.device.kemPub
  const userId = creds.userId
  const scope: ScopePreset = opts.scope ?? scopes.rootAll()
  const refreshMarginSec = opts.refreshMarginSec ?? DEFAULT_REFRESH_MARGIN_SEC
  const clock = opts.clock ?? (() => Date.now() / 1000)
  const underlying = opts.fetchFn ?? globalThis.fetch.bind(globalThis)

  let capExp = 0
  let authHeader = ""

  function setCap(cap: CapCert): void {
    capExp = cap.exp
    const capJson = stableStringify(cap)
    authHeader =
      "Cap " + getBase64().encode(new TextEncoder().encode(capJson))
  }

  async function refreshCapIfNeeded(): Promise<void> {
    if (Math.floor(clock()) < capExp - refreshMarginSec) return
    // Same priv/pub keys → same userId → role is preserved across refresh.
    const cap = await mintDeviceCap(
      edPriv,
      edPub,
      { edPubHex: edPub, kemPubHex: kemPub },
      scope,
    )
    setCap(cap)
  }

  setCap(creds.capCert)

  const signedFetch: typeof fetch = async (input, init) => {
    await refreshCapIfNeeded()
    const request = new Request(input as RequestInfo, init)
    const method = request.method.toUpperCase() as SignableMethod
    // Read the body bytes for the signature (sha256(body) is part of the
    // canonical input). `Request` is single-use, so rebuild it with the bytes.
    const bodyBuf = await request.clone().arrayBuffer()
    const body = new Uint8Array(bodyBuf)

    const url = new URL(request.url)
    // Mirror the server's path reconstruction: decoded pathname + search.
    const pathAndQuery = url.pathname + url.search
    // Full host incl. port for non-default ports, matching the server's
    // host-from-request reconstruction.
    const host = url.host

    const sig = await signRequest(
      { method, pathAndQuery, body, host },
      edPriv,
    )

    const headers = new Headers(request.headers)
    headers.set(HEADER_AUTHORIZATION, authHeader)
    headers.set(HEADER_SIG, sig.sig)
    headers.set(HEADER_TS, String(sig.ts))
    headers.set(HEADER_NONCE, sig.nonce)

    return underlying(url.toString(), {
      method,
      headers,
      body: body.byteLength > 0 ? body : undefined,
    })
  }

  return { fetch: signedFetch, userId }
}
