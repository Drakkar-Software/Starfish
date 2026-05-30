/**
 * Cap-cert role resolver.
 *
 * Builds a {@link RoleResolver} that authenticates a request by parsing
 * an `Authorization: Cap <base64-cert>` header together with the
 * `X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce` triplet, then
 * synthesizes a role set from the cap-cert's scope.
 *
 * This is opt-in: pass the returned resolver as `SyncRouterOptions.roleResolver`
 * to enable v3 cap-cert auth. The existing Bearer-token + custom
 * `roleResolver` path remains the default when this is not wired in.
 */

import type { Context } from "hono"
import {
  verifyCapCert,
  verifyRequestSignature,
  isWithinClockSkew,
  getBase64,
  pathGlobMatch,
  isRootDeviceCap,
  userIdFromPubHex,
  HEADER_AUTHORIZATION as HEADER_AUTH,
  HEADER_SIG,
  HEADER_TS,
  HEADER_NONCE,
  HEADER_PUB,
  type CapCert,
  type SignableRequest,
} from "@drakkar.software/starfish-protocol"
import type { RoleResolver, AuthResult } from "./route-builder.js"
import type { NonceCache } from "../auth/nonce-cache.js"
import type { RevocationStore } from "../auth/revocation-store.js"
import {
  composePluginValidators,
  defaultServerPlugin,
  type CapCertValidator,
  type ServerPlugin,
} from "../plugins.js"
import { ROLE_PUBLIC, ROLE_ROOT_DEVICE, IDENTITY_KEY } from "../constants.js"

/** Options for {@link createCapCertRoleResolver}. */
export interface CapResolverOptions {
  /** Replay-protection nonce cache (per-process or shared). */
  nonceCache: NonceCache
  /** Revocation list lookup. */
  revocationStore: RevocationStore
  /**
   * Whether to allow requests without an `Authorization: Cap` header.
   * When `true` (default), the resolver returns `{identity: "", roles: ["public"]}`.
   * When `false`, missing/malformed Authorization throws a 401.
   */
  allowAnonymous?: boolean
  /**
   * Hard upper bound on the request body, in bytes, enforced BEFORE any
   * body buffering. Writes whose `Content-Length` header is absent or
   * greater than this value are rejected with HTTP 413. Defaults to
   * 64 KB — enough for the protocol's JSON envelopes.
   *
   * The route-builder's per-collection `checkBodyLimit` still applies
   * downstream and may impose a stricter limit; this option is a
   * pre-auth DoS amplifier guard, not a replacement for it.
   */
  maxBodyBytes?: number
  /**
   * Hard upper bound on the `Authorization: Cap <...>` header value, in
   * bytes. Headers longer than this are rejected with HTTP 401 and
   * message `cap-too-large` before any base64 / JSON parsing is
   * attempted. Defaults to 8 KB.
   */
  maxCapHeaderBytes?: number
  /**
   * Plugins contributing per-kind cap-cert validators. Validators run
   * **after** the core `verifyCapCert` checks (sig + window + baseline
   * well-formedness) and may throw to reject a request.
   *
   * Strict-kind dispatch is **always** active (secure by default): a cap
   * whose `kind` has no registered validator is rejected with HTTP 401.
   * When this option is omitted, the built-in device-only
   * `defaultServerPlugin` is used — `device` caps are accepted (baseline is
   * sufficient for an issuer proxy) but `member` caps are rejected until a
   * validator for them is wired. To accept member caps, pass
   * `plugins: [defaultServerPlugin, sharingServerPlugin]`. An explicit empty
   * list (`plugins: []`) registers no kinds → every cap is rejected
   * (anonymous-only).
   */
  plugins?: ServerPlugin[]
  /**
   * When a cap arrives whose `kind` is not registered by any plugin, reject
   * the request with HTTP 401. Default `true` (secure). Set to `false` to
   * fall through and accept unregistered kinds with baseline checks only —
   * useful during a phased rollout, but it re-opens the member-cap bypass
   * (member barriers live in `sharingServerPlugin`), so keep it `true` in
   * production.
   */
  strictKindDispatch?: boolean
}

/**
 * Error subclass used by the resolver to surface a desired HTTP status
 * back to the route-builder. The route-builder's existing `_check_auth`
 * machinery generally returns 401 on any resolver throw; future versions
 * may consult this `.status` field to surface 403 instead.
 */
export class CapAuthError extends Error {
  public readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
    this.name = "CapAuthError"
  }
}

// Request-auth header names are defined once in `starfish-protocol` (imported
// above) so the client and this resolver cannot drift:
//   HEADER_PUB  — the presenter's Ed25519 pubkey for an `audience` cap (which
//     binds no single subject); the per-request signature is verified against it
//     and, when the cap carries an `aud` allow-list, membership is checked.
//     Ignored for device/member caps, whose verifying key is `cert.sub`.

/** A presenter Ed25519 pubkey: 64-char lowercase hex (32-byte). */
const PUB_HEX_RE = /^[0-9a-f]{64}$/

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"])

const DEFAULT_MAX_BODY_BYTES = 64 * 1024
const DEFAULT_MAX_CAP_HEADER_BYTES = 8 * 1024

/**
 * Parse a header that must be a base-10 integer, returning `null` when it is
 * not. Defined so TypeScript and Python accept exactly the same strings: JS
 * `Number()` would silently accept `"0x10"`, `"1e3"`, `"12.5"`, and
 * whitespace-padded values that Python's `int()` rejects, which made the same
 * request authenticate differently per server. The shared `^-?\d+$` rule
 * rejects all of those on both sides.
 */
function parseIntegerHeader(value: string): number | null {
  if (!/^-?\d+$/.test(value)) return null
  const n = Number(value)
  return Number.isFinite(n) ? n : null
}

function parseCapHeader(value: string): CapCert | null {
  if (!value.startsWith("Cap ")) return null
  const b64 = value.slice("Cap ".length).trim()
  if (!b64) return null
  let json: string
  try {
    // Use the injectable base64 codec (NOT Node's `Buffer`) so the resolver
    // runs unchanged on non-Node runtimes such as Cloudflare Workers.
    json = new TextDecoder().decode(getBase64().decode(b64))
  } catch {
    return null
  }
  try {
    return JSON.parse(json) as CapCert
  } catch {
    return null
  }
}

function pathAndQueryFromUrl(url: string): string {
  try {
    const u = new URL(url)
    return u.pathname + u.search
  } catch {
    return url
  }
}

/**
 * Extract the host portion of the inbound request URL. The host is
 * folded into the canonical signing input on the verifier side; the
 * client must have signed with the same host or verification fails.
 * Returns `""` for an unparseable URL — the client's empty-host path
 * still verifies symmetrically against `""`.
 */
function hostFromUrl(url: string): string {
  try {
    return new URL(url).host
  } catch {
    return ""
  }
}

function synthesizeRoles(cert: CapCert): string[] {
  const roles = new Set<string>()
  const ops = cert.scope.ops
  for (const op of ops) {
    for (const col of cert.scope.collections) {
      roles.add(`cap:${op}:${col}`)
    }
  }
  if (cert.kind === "member" || cert.kind === "audience") {
    // Both are issuer-scoped grants: carry the issuer identity so path-owner
    // role enrichers can admit the grant against the owner's namespace.
    for (const col of cert.scope.collections) {
      roles.add(`delegated:${cert.issUserId}:${col}`)
    }
  }
  // A self-signed device cap (iss === sub) is the root device; mark it so
  // `rootOnly` collections can admit it and reject every delegated cap.
  if (isRootDeviceCap(cert)) {
    roles.add(ROLE_ROOT_DEVICE)
  }
  // ROLE_SELF is NOT emitted here — the route-builder's identity-vs-params
  // check adds it conditionally when `params.identity === auth.identity`,
  // which centralizes the rule and prevents `self` from leaking across users.
  return [...roles]
}

/**
 * Percent-decode each segment, then collapse empty and `.` segments, so the
 * scope-match path is the SAME string the storage layer keys on.
 *
 * The router (Hono) percent-decodes path params before composing the document
 * key, so scope matching must decode too. Otherwise an encoded character — e.g.
 * `_%6beyring` (which decodes to `_keyring`) — slips past a deny like
 * `!col/_keyring` while the write still lands on the decoded `col/_keyring`
 * key: a scoped member could overwrite the owner-only keyring. Decoding can
 * only make a deny fire on *more* paths (denies are written decoded), so it is
 * safe directionally. Decoding is per-segment and mirrors `decodeURIComponent`;
 * a malformed escape is left raw. (`..` / `//` / control chars in the resolved
 * key are independently rejected by `isUnsafeDocumentKey` before the store is
 * touched, so they cannot be smuggled in via an encoded form here either.)
 *
 * `col/_keyring/`, `col//_keyring`, `col/./_keyring` and `col/_%6beyring` all
 * canonicalize to `col/_keyring`.
 */
function canonicalizeRequestPath(requestPath: string): string {
  return requestPath
    .split("/")
    .map(decodePathSegment)
    .filter((seg) => seg !== "" && seg !== ".")
    .join("/")
}

/** Percent-decode one path segment; leave it raw if the escape is malformed. */
function decodePathSegment(seg: string): string {
  try {
    return decodeURIComponent(seg)
  } catch {
    return seg
  }
}

/**
 * Glob match against `scope.paths` entries. Supports `*` (any run of non-slash
 * characters), `**` (any run including slashes), and a leading `!` as a denylist
 * marker.
 *
 * The per-glob matching is delegated to the protocol's `pathGlobMatch` so the
 * request-path enforcement here and the member-cap scope barriers in
 * `starfish-sharing` share one definition of glob semantics — a divergence
 * between the two would let a cap clear the mint/validation barrier yet match
 * a path the resolver grants.
 *
 * The request path is canonicalized (empty/`.` segments collapsed) before
 * matching, and a deny rule `!path` covers both `path` and any descendant
 * `path/...` — so an owner-only deny like `!col/_keyring` cannot be side-stepped
 * with `col/_keyring/`, `col/_keyring/x` or `col/./_keyring`.
 *
 * Returns `true` when no `scopePaths` are specified (no path restriction),
 * or when at least one allow rule matches AND no deny rule matches.
 */
export function matchScopePath(
  requestPath: string,
  scopePaths: string[] | undefined,
): boolean {
  if (!scopePaths || scopePaths.length === 0) return true
  const canonical = canonicalizeRequestPath(requestPath)
  const allows: string[] = []
  const denies: string[] = []
  for (const entry of scopePaths) {
    if (entry.startsWith("!")) denies.push(entry.slice(1))
    else allows.push(entry)
  }
  if (allows.length === 0) return false
  const allowed = allows.some((p) => pathGlobMatch(p, canonical))
  if (!allowed) return false
  // A deny covers the exact path AND any descendant (`<deny>/...`), so a
  // sibling/child read cannot slip past an owner-only deny.
  const denied = denies.some(
    (p) => pathGlobMatch(p, canonical) || pathGlobMatch(`${p}/**`, canonical),
  )
  return !denied
}

/**
 * Strip the action prefix (`/pull/`, `/push/`, `/list/`) and optional
 * namespace segment from a request path, returning the storage-path form
 * that `scope.paths` globs match against. Drops the query string.
 *
 * Examples:
 *   `/pull/notes/abc?x=1`              → `notes/abc`
 *   `/push/users/123/data`              → `users/123/data`
 *   `/myns/pull/shared/abc`             → `shared/abc`
 *   `/list/shared`                      → `shared`
 *   `/foo/bar` (no recognised action)   → `foo/bar` (best-effort)
 */
function stripActionPrefix(pathAndQuery: string): string {
  const qIdx = pathAndQuery.indexOf("?")
  const pathOnly = qIdx >= 0 ? pathAndQuery.slice(0, qIdx) : pathAndQuery
  const trimmed = pathOnly.startsWith("/") ? pathOnly.slice(1) : pathOnly
  const segs = trimmed.split("/")
  // Find first action segment.
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i]
    if (s === "pull" || s === "push" || s === "list") {
      return segs.slice(i + 1).join("/")
    }
  }
  return trimmed
}

/**
 * True for the batch-pull routes (`/batch/pull` and `/<ns>/batch/pull`). These
 * carry no storage path in their URL — they name collections + params in the
 * query — so the per-request `scope.paths` check cannot run at the resolver; the
 * batch handler re-checks each RESOLVED key against `scope.paths` instead. The
 * length + action-prefix guard keeps a standalone pull of a collection literally
 * named `batch/pull` (`/pull/batch/pull`) from being mistaken for the batch route.
 */
function isBatchPullPath(pathAndQuery: string): boolean {
  const qIdx = pathAndQuery.indexOf("?")
  const pathOnly = qIdx >= 0 ? pathAndQuery.slice(0, qIdx) : pathAndQuery
  const segs = pathOnly.split("/").filter((s) => s.length > 0)
  const n = segs.length
  if (n < 2 || segs[n - 2] !== "batch" || segs[n - 1] !== "pull") return false
  if (n === 2) return true // /batch/pull
  // /<ns>/batch/pull — a single namespace segment, never an action prefix.
  return n === 3 && segs[0] !== "pull" && segs[0] !== "push" && segs[0] !== "list"
}

// ─── Private orchestrator helpers ────────────────────────────────────────────
//
// Each helper covers one concern of the resolver pipeline. They MUST preserve
// the verify ordering — cheap O(1) checks (header presence, clock skew) run
// before any Ed25519 verify burns CPU; the cap-cert verify (~200 µs) is the
// most expensive step and lives in the orchestrator, NOT inside any helper here.

/**
 * Parse and shape-validate the `Authorization: Cap …` header.
 *
 * Returns `null` when the header is missing/non-`Cap` AND
 * `opts.allowAnonymous` is `true` — the orchestrator turns that into a
 * `(identity: "", roles: ["public"])` result. Throws `CapAuthError(401)`
 * for: missing header with `allowAnonymous=false`, header over the size
 * cap, malformed base64/JSON, or any shape-validation failure.
 *
 * Does NOT perform the Ed25519 cap-cert verify — that is the orchestrator's
 * responsibility (kept there so the verify ordering is observable in one place).
 */
function parseAndValidateCapHeader(
  c: Context,
  opts: {
    allowAnonymous: boolean
    maxCapHeaderBytes: number
  },
): CapCert | null {
  const authHeader = c.req.header(HEADER_AUTH)
  if (!authHeader || !authHeader.startsWith("Cap ")) {
    if (opts.allowAnonymous) return null
    throw new CapAuthError(401, "missing Authorization: Cap header")
  }
  // Bound the Authorization header BEFORE base64/JSON parsing.
  if (authHeader.length > opts.maxCapHeaderBytes) {
    throw new CapAuthError(401, "cap-too-large")
  }
  const cert = parseCapHeader(authHeader)
  if (!cert) {
    throw new CapAuthError(401, "malformed cap-cert in Authorization header")
  }
  return cert
}

/**
 * Read and parse the request-signature header triplet
 * (`X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce`).
 *
 * Returns `{sig, ts, nonce}` on success. Throws `CapAuthError(401)` when
 * any header is missing or `ts` is not a finite number. The caller does
 * the clock-skew check next — keeping the skew gate in the orchestrator
 * makes the verify ordering visible without indirection.
 */
function readSigHeaders(c: Context): { sig: string; ts: number; nonce: string } {
  const sigB64 = c.req.header(HEADER_SIG)
  const tsHeader = c.req.header(HEADER_TS)
  const nonceB64 = c.req.header(HEADER_NONCE)
  if (!sigB64 || !tsHeader || !nonceB64) {
    throw new CapAuthError(401, "missing request signature headers")
  }
  const ts = parseIntegerHeader(tsHeader)
  if (ts === null) {
    throw new CapAuthError(401, "invalid X-Starfish-Ts")
  }
  return { sig: sigB64, ts, nonce: nonceB64 }
}

/**
 * DoS amplifier guard. Validate the `Content-Length` header BEFORE
 * touching the body buffer; only after the header passes do we read the
 * stream. For non-write methods (`GET`, `HEAD`, etc.) the body is treated
 * as the empty buffer regardless of any payload sent.
 *
 * Throws `CapAuthError(413)` for: missing `Content-Length` on a write,
 * non-numeric/negative `Content-Length`, or `Content-Length` greater than
 * `maxBodyBytes`. The route-builder's per-collection `checkBodyLimit`
 * still applies downstream and may impose a stricter limit.
 */
async function bufferAndCheckBody(
  c: Context,
  method: string,
  maxBodyBytes: number,
): Promise<Uint8Array> {
  if (!WRITE_METHODS.has(method)) return new Uint8Array(0)
  const contentLength = c.req.header("content-length")
  if (contentLength == null) {
    throw new CapAuthError(413, "missing Content-Length on write")
  }
  const parsed = parseIntegerHeader(contentLength)
  if (parsed === null || parsed < 0) {
    throw new CapAuthError(413, "invalid Content-Length")
  }
  if (parsed > maxBodyBytes) {
    throw new CapAuthError(413, "request body too large")
  }
  try {
    const buf = await c.req.arrayBuffer()
    return new Uint8Array(buf)
  } catch {
    return new Uint8Array(0)
  }
}

/**
 * Bind `auth.identity` to the cap-cert kind:
 *   - `device`   caps proxy for the issuer → `issUserId`
 *   - `member`   caps are scoped grants to the subject → `subUserId`
 *   - `audience` caps bind no subject → the presenter's own userId,
 *     `userIdFromPubHex(verifyingPubHex)`
 *
 * This is the cryptographic root of "device of A cannot access B's data" — a
 * device cap's identity is always its issuer, and an audience presenter's
 * identity is the hash of the key they proved possession of, so neither can
 * pose as another user even if `scope.paths` was forged to look permissive.
 *
 * Throws `CapAuthError(401)` for a `member` cap missing `subUserId` and for any
 * unrecognized kind. Strict-kind dispatch should already have rejected those
 * cases upstream; this is defense in depth.
 */
function bindAuthIdentity(cert: CapCert, verifyingPubHex: string): string {
  if (cert.kind === "device") return cert.issUserId
  if (cert.kind === "member") {
    if (!cert.subUserId) {
      throw new CapAuthError(401, "member cap missing subUserId")
    }
    return cert.subUserId
  }
  if (cert.kind === "audience") return userIdFromPubHex(verifyingPubHex)
  throw new CapAuthError(401, `unsupported cap-cert kind "${(cert as CapCert).kind}"`)
}

/**
 * Resolve the Ed25519 pubkey the per-request signature must verify against:
 *   - device/member → the cap's single subject `cert.sub`
 *   - audience      → the presenter pubkey from the `X-Starfish-Pub` header
 *
 * For audience caps the header is mandatory (every redeemer signs as self) and
 * must be 64-char lowercase hex; missing/malformed → `CapAuthError(401)`.
 */
function resolveVerifyingPubHex(cert: CapCert, pubHeader: string | undefined): string {
  if (cert.kind === "audience") {
    if (!pubHeader || !PUB_HEX_RE.test(pubHeader)) {
      throw new CapAuthError(401, "missing or malformed X-Starfish-Pub for audience cap")
    }
    return pubHeader
  }
  if (typeof cert.sub !== "string") {
    throw new CapAuthError(401, "cap-cert missing subject")
  }
  return cert.sub
}

/**
 * Read the route's `{identity}` path param defensively. Returns `undefined`
 * when the call site has no router context (e.g. `/config`) or when the
 * Hono Context's `param()` accessor is not function-shaped.
 */
function readIdentityParam(c: Context): string | undefined {
  try {
    const p = (c.req as { param?: (key: string) => string | undefined }).param
    return typeof p === "function" ? p.call(c.req, IDENTITY_KEY) : undefined
  } catch {
    return undefined
  }
}

/**
 * Create a {@link RoleResolver} that authenticates via cap-cert + request
 * signature, with replay protection and revocation lookup.
 */
export function createCapCertRoleResolver(opts: CapResolverOptions): RoleResolver {
  const allowAnonymous = opts.allowAnonymous ?? true
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES
  const maxCapHeaderBytes = opts.maxCapHeaderBytes ?? DEFAULT_MAX_CAP_HEADER_BYTES
  const strictKindDispatch = opts.strictKindDispatch ?? true
  // Strict-kind dispatch is ALWAYS active (secure by default). With no
  // `plugins`, fall back to the built-in device-only `defaultServerPlugin`:
  // `device` caps are accepted (baseline suffices for an issuer proxy), but
  // `member`/unknown kinds are rejected until the app wires a validator
  // (e.g. `sharingServerPlugin`). An explicit empty list (`plugins: []`)
  // registers no kinds → every cap is rejected (anonymous-only).
  const pluginValidators: Map<CapCert["kind"], CapCertValidator[]> =
    composePluginValidators(opts.plugins ?? [defaultServerPlugin])

  return async (c: Context): Promise<AuthResult> => {
    // Parse the cap-cert header (anonymous short-circuit lives here).
    const cert = parseAndValidateCapHeader(c, { allowAnonymous, maxCapHeaderBytes })
    if (cert === null) return { identity: "", roles: [ROLE_PUBLIC] }

    // Cheap O(1) checks BEFORE the Ed25519 cap-cert verify.
    const { sig: sigB64, ts, nonce: nonceB64 } = readSigHeaders(c)
    const nowMs = Date.now()
    if (!isWithinClockSkew(ts, nowMs)) {
      throw new CapAuthError(401, "request timestamp outside clock skew")
    }

    // Ed25519 cap-cert verify — kept in the orchestrator to make the
    // verify ordering reviewable in one place.
    const nowSec = Math.floor(nowMs / 1000)
    const certResult = await verifyCapCert(cert, { now: nowSec })
    if (!certResult.ok) {
      throw new CapAuthError(401, `cap-cert ${certResult.reason ?? "invalid"}`)
    }

    // Strict-kind dispatch (secure by default). Look up validators for
    // `cert.kind`; a kind with no registered validator is rejected 401
    // (unless `strictKindDispatch` was explicitly disabled for a phased
    // rollout). Each validator runs in registration order; any throw rejects
    // the request. This is what stops a forged `member` cap from being
    // accepted on a resolver that has not wired `sharingServerPlugin`.
    {
      const validators = pluginValidators.get(cert.kind)
      if (validators === undefined || validators.length === 0) {
        if (strictKindDispatch) {
          throw new CapAuthError(
            401,
            `cap-cert kind "${cert.kind}" has no registered validator`,
          )
        }
      } else {
        for (const validator of validators) {
          try {
            validator(cert)
          } catch (e) {
            const msg = e instanceof Error ? e.message : String(e)
            throw new CapAuthError(401, `cap-cert plugin reject: ${msg}`)
          }
        }
      }
    }

    // Body buffer + Content-Length pre-auth guard.
    const methodUpper = c.req.method.toUpperCase() as "GET" | "POST" | "PUT" | "DELETE"
    const bodyBytes = await bufferAndCheckBody(c, methodUpper, maxBodyBytes)

    // Binary blob uploads are signed by the client (`pushBlob`) with an EMPTY body —
    // clients don't fold large/streamed blob bytes into the per-request signature, and
    // blob integrity is provided out-of-band by the content seal (AES-GCM bound to the
    // storage path). The discriminator is the content type: a JSON write
    // (`application/json`) signs the real body; ANY other (non-empty) media type is a
    // blob upload signed over an empty body. An empty/missing content type is treated
    // as non-blob (sign the body) so a missing header can't dodge body-signing; a JSON
    // collection still rejects a non-JSON content type at the handler's MIME check. The
    // media type is compared on its prefix (params stripped) so a crafted
    // `application/json; x=octet-stream` can't flip the gate. Mirrored in cap_resolver.py.
    const mediaType = (c.req.header("content-type") ?? "").split(";")[0]!.trim().toLowerCase()
    const isBlobUpload = mediaType !== "" && mediaType !== "application/json"
    const signingBody = isBlobUpload ? new Uint8Array(0) : bodyBytes

    // Resolve the verifying pubkey: device/member → `cert.sub`; audience → the
    // presenter pubkey from `X-Starfish-Pub` (mandatory + validated there).
    const verifyingPubHex = resolveVerifyingPubHex(cert, c.req.header(HEADER_PUB))

    // Verify the per-request Ed25519 signature, bound to host.
    const req: SignableRequest = {
      method: methodUpper,
      pathAndQuery: pathAndQueryFromUrl(c.req.url),
      body: signingBody,
      host: hostFromUrl(c.req.url),
    }
    const sigOk = await verifyRequestSignature(
      req,
      { sig: sigB64, ts, nonce: nonceB64 },
      verifyingPubHex,
    )
    if (!sigOk) throw new CapAuthError(401, "bad request signature")

    // Audience allow-list membership. Runs AFTER the signature proves the
    // presenter holds `verifyingPubHex`'s private key, and BEFORE the
    // nonce-cache write so a non-member never consumes a cache slot. When `aud`
    // is absent, any identity may redeem.
    if (
      cert.kind === "audience" &&
      cert.aud !== undefined &&
      !cert.aud.includes(verifyingPubHex)
    ) {
      throw new CapAuthError(403, "presenter is not in the cap audience")
    }

    // Replay protection — the nonce must not have been seen yet. Keyed by the
    // verifying pubkey so two audience redeemers never share a nonce namespace.
    if (!(await opts.nonceCache.checkAndRemember(verifyingPubHex, nonceB64, nowMs))) {
      throw new CapAuthError(401, "nonce replay")
    }

    // Revocation list lookup. An audience cap has no single subject, so it is
    // revoked by nonce alone — the issuer writes `sub: ""`, matched by passing
    // "" here; per-cap revocation still works because the nonce is unique.
    const revocationSub = cert.kind === "audience" ? "" : (cert.sub ?? "")
    if (opts.revocationStore.isRevoked(cert.iss, revocationSub, cert.nonce)) {
      throw new CapAuthError(401, "cap-cert revoked")
    }

    // Bind auth.identity to the cap-cert.
    const identity = bindAuthIdentity(cert, verifyingPubHex)

    // scope.paths glob matching (with `{identity}` substitution and
    // `!`-prefixed denylist). Strips the `/pull/`, `/push/`, `/list/`
    // action prefix so the glob matches the storage-path form.
    const storagePath = stripActionPrefix(req.pathAndQuery)
    const expandedPaths = cert.scope.paths?.map((p) =>
      p.split("{identity}").join(identity),
    )
    // A member/audience cap is a SCOPED grant — it must carry an explicit path
    // scope. Only a device/root cap (a proxy for the issuer's full authority)
    // may be path-unrestricted. Without this, a member/audience cap minted with
    // no `scope.paths` would clear the gate for every path
    // (`matchScopePath(_, undefined)` === true), reaching the owner-only
    // `_keyring`/`_members`. Defense-in-depth alongside the mint/server-side
    // shape barrier (`assertScopeBarriers`).
    if (cert.kind !== "device" && (!expandedPaths || expandedPaths.length === 0)) {
      throw new CapAuthError(403, "member/audience cap must carry an explicit scope.paths")
    }
    // Batch pull carries no single storage path in its URL, so the per-request
    // path-scope check can't run here — the batch handler enforces `scope.paths`
    // per RESOLVED key instead. Every other verify step (sig, nonce, revocation)
    // still ran above, and `scopePaths` is returned below for that per-key check.
    if (!isBatchPullPath(req.pathAndQuery) && !matchScopePath(storagePath, expandedPaths)) {
      throw new CapAuthError(403, "request path is outside cap scope")
    }

    // `{identity}` URL-param binding: when the route exposes an
    // `identity` path param, it must equal `auth.identity`.
    const paramIdentity = readIdentityParam(c)
    if (paramIdentity != null && paramIdentity !== identity) {
      throw new CapAuthError(403, "request identity does not match cap-bound identity")
    }

    // Synthesize role bag from cap scope.
    const roles = synthesizeRoles(cert)
    // Carry the expanded scope so the route layer can authorize sibling reads
    // (e.g. the ?withKeyring=1 `<key>/_keyring` shortcut) against the same
    // paths the data request was checked against. `presenter` carries the key
    // that signed THIS request (already verified above) so the append handler
    // can bind a signed element's author to its authenticated writer.
    return {
      identity,
      roles,
      scopePaths: expandedPaths,
      presenter: { pubHex: verifyingPubHex },
    }
  }
}
