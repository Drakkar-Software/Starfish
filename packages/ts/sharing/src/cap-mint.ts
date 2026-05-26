/**
 * Member cap-cert minting + the member-side scope presets.
 *
 * Higher-level convenience over the protocol package's `signCapCert` /
 * `assertCapCertWellFormed`. The mint helper does the boilerplate and forces
 * `scope.collections` to the single collection passed by the caller.
 */

import {
  assertCapCertWellFormed,
  DEFAULT_ALG,
  getBase64,
  getCrypto,
  pathGlobMatch,
  signCapCert,
  suiteHasSeparateKem,
  type Alg,
  type CapCert,
  type UnsignedCapCert,
} from "@drakkar.software/starfish-protocol"

/** Member-cap well-formedness codes raised by {@link assertMemberCapShape}. */
export type MemberCapShapeCode =
  | "member-missing-sub-userid"
  | "member-self"
  | "member-wildcard-collections"
  | "member-multi-collection"
  | "member-private-path"
  | "member-members-not-denied"
  | "member-keyring-not-denied"

/** Audience-cap well-formedness codes raised by {@link assertAudienceCapShape}. */
export type AudienceCapShapeCode =
  | "audience-wildcard-collections"
  | "audience-multi-collection"
  | "audience-private-path"
  | "audience-members-not-denied"
  | "audience-keyring-not-denied"

function throwCoded(code: MemberCapShapeCode, message: string): never {
  const err = new Error(message) as Error & { code: MemberCapShapeCode }
  err.code = code
  throw err
}

function throwWithCode(code: string, message: string): never {
  const err = new Error(message) as Error & { code: string }
  err.code = code
  throw err
}

/** Operations + paths + collections a minted cap-cert authorizes. */
export interface ScopePreset {
  ops: ("read" | "write" | "list")[]
  collections: string[]
  paths?: string[]
}

/** Built-in scope presets.
 *
 *  All `paths` entries use `**` (matches across slashes) so multi-segment
 *  storage paths like `users/<userId>/notes/_keyring` are reachable. A single
 *  `*` would only match one path segment. The member presets (`readOnly`,
 *  `writer`) deny `<col>/_keyring` and `<col>/_members` because those are
 *  owner-only — a member cap that could reach them is rejected at mint and at
 *  server validation time.
 *
 *  `admin` carries no such deny, so it is only valid for a **device** cap
 *  (`mintDeviceCap`): a device cap proxies for the issuer (the owner), so it
 *  legitimately manages the owner's own keyring and member directory. Passing
 *  `admin` to `mintMemberCap` is rejected — a member keeps its own identity
 *  and must never gain authority over `_keyring`/`_members`.
 */
export const scopes = {
  /** Read-only access to a single collection (including nested storage paths). */
  readOnly: (c: string): ScopePreset => ({
    ops: ["read", "list"],
    paths: [`${c}/**`, `!${c}/_members`],
    collections: [c],
  }),
  /** Read + list + write to a collection, denying access to its `_keyring` and `_members`. */
  writer: (c: string): ScopePreset => ({
    ops: ["read", "list", "write"],
    paths: [`${c}/**`, `!${c}/_keyring`, `!${c}/_members`],
    collections: [c],
  }),
  /**
   * Full read+list+write to a collection with no denylist — manages the
   * keyring and member directory. Valid only for a **device** cap
   * (`mintDeviceCap`); `mintMemberCap` rejects it because a member cap must
   * never reach `<col>/_keyring` or `<col>/_members`.
   */
  admin: (c: string): ScopePreset => ({
    ops: ["read", "list", "write"],
    paths: [`${c}/**`],
    collections: [c],
  }),
}

/** Optional knobs for the mint helper. */
export interface MintOpts {
  /** TTL in seconds. Default 30 days. Ignored when `expiresAt` is set. */
  ttlSec?: number
  /**
   * Absolute expiry, unix seconds. When set it wins over `ttlSec` and maps
   * directly to the cap's `exp`. Must be strictly after `nbf`.
   */
  expiresAt?: number
  /** Not-before, unix seconds. Defaults to `Math.floor(Date.now()/1000)`. */
  nbf?: number
  /** Random nonce bytes (16 recommended). Defaults to fresh randomness. */
  nonce?: Uint8Array
  /** Issuer's crypto suite (governs the cap signature). Defaults to the system default. */
  alg?: Alg
  /** Subject's signing suite (governs `sub` + per-request sigs). Defaults to `alg`. */
  subAlg?: Alg
  /** Subject's KEM suite (governs `subKem`). Defaults to `subAlg`. */
  subKemAlg?: Alg
}

/** Optional knobs for {@link mintAudienceCap}. */
export interface AudienceMintOpts extends MintOpts {
  /**
   * Allow-list of redeemer Ed25519 pubkeys (64-char lowercase hex). When
   * provided (non-empty) only these identities may redeem; omit for "any
   * identity". Maps to the cap's `aud`.
   */
  audience?: string[]
}

const DEFAULT_TTL_SEC = 30 * 24 * 3600
const NONCE_LEN = 16

/**
 * Resolve a cap's `nbf`/`exp` from the mint opts. `expiresAt` wins over
 * `ttlSec`; otherwise `exp = nbf + (ttlSec ?? DEFAULT_TTL_SEC)`. Rejects an
 * `expiresAt` that is not strictly after `nbf` so the cap never carries an
 * inverted validity window. Identical rule in TS and Python.
 */
function resolveValidity(opts: MintOpts): { nbf: number; exp: number } {
  const nbf = opts.nbf ?? Math.floor(Date.now() / 1000)
  if (opts.expiresAt !== undefined) {
    if (opts.expiresAt <= nbf) {
      throw new Error("expiresAt-not-after-nbf")
    }
    return { nbf, exp: opts.expiresAt }
  }
  return { nbf, exp: nbf + (opts.ttlSec ?? DEFAULT_TTL_SEC) }
}

function bytesToHex(bytes: Uint8Array): string {
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0")
  return s
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length")
  // Reject non-hex chars: `parseInt` → NaN → 0, silently zeroing malformed input.
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error("hex string has invalid characters")
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  }
  return out
}

async function userIdFromPubHex(pubHex: string): Promise<string> {
  const pubBytes = hexToBytes(pubHex)
  const digest = await getCrypto().subtle.digest("SHA-256", pubBytes as BufferSource)
  return bytesToHex(new Uint8Array(digest)).slice(0, 32)
}

function defaultNonce(): Uint8Array {
  const buf = new Uint8Array(NONCE_LEN)
  getCrypto().getRandomValues(buf)
  return buf
}

/**
 * Mint a `member` cap-cert: the subject keeps their own identity and
 * receives a scoped role grant from the issuer.
 *
 * `collection` is the single collection name this cap grants access to;
 * it is forced into `scope.collections` (overriding any value the caller
 * may have passed in `scope`). Member caps are collection-scoped by
 * design — passing more than one collection is rejected at
 * well-formedness time.
 *
 * Throws `Error` with `.code` of:
 * - `"member-self"` when sub equals the issuer.
 * - `"member-wildcard-collections"` when scope.collections includes `"*"`.
 * - `"member-multi-collection"` when scope.collections.length !== 1.
 * - `"member-private-path"` when a scope path lands in the issuer's
 *   `users/<issUserId>/` namespace.
 * - `"member-members-not-denied"` when scope allows `<col>/_members` without
 *   an explicit deny.
 * - `"member-keyring-not-denied"` when write scope allows `<col>/_keyring`
 *   without an explicit deny.
 */
export async function mintMemberCap(
  issEdPrivHex: string,
  issEdPubHex: string,
  sub: { edPubHex: string; kemPubHex: string; userIdHex: string },
  collection: string,
  scope: ScopePreset,
  opts: MintOpts = {},
): Promise<CapCert> {
  const { nbf, exp } = resolveValidity(opts)
  const nonceBytes = opts.nonce ?? defaultNonce()
  const nonce = getBase64().encode(nonceBytes)
  const issAlg = opts.alg ?? DEFAULT_ALG
  const subAlg = opts.subAlg ?? issAlg
  const subKemAlg = opts.subKemAlg ?? subAlg
  // subKem is omitted only when the KEM key IS the signing key (same-suite
  // single-key suite); otherwise it carries a distinct KEM pubkey of suite
  // `subKemAlg`. The keyring now wraps under any suite's ECDH (`recipientKem`),
  // so every `subKemAlg` is mintable.
  const kemKeyIsSignKey = subKemAlg === subAlg && !suiteHasSeparateKem(subKemAlg)
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "member",
    issAlg,
    subAlg,
    ...(opts.subKemAlg !== undefined && opts.subKemAlg !== subAlg ? { subKemAlg } : {}),
    iss: issEdPubHex,
    issUserId: await userIdFromPubHex(issEdPubHex),
    sub: sub.edPubHex,
    ...(kemKeyIsSignKey ? {} : { subKem: sub.kemPubHex }),
    subUserId: sub.userIdHex,
    scope: { ...scope, collections: [collection] },
    nbf,
    exp,
    nonce,
  }
  assertMemberCapShape(unsigned)
  return signCapCert(unsigned, issEdPrivHex)
}

/**
 * Assert the structural shape of a `member` cap-cert. This is the
 * authoritative owner of the member-cap rules — `starfish-protocol` only
 * checks the generic iss/sub-userId relations; the member-specific barriers
 * live here so the sharing extension owns them end-to-end.
 *
 * Used by `mintMemberCap` (client-side mint guard) and by
 * `sharingServerPlugin` (server-side validation under the cap-resolver's
 * plugin dispatch). Exposed for apps that want to validate a member cap
 * standalone.
 *
 * Throws `Error` with `.code` set to one of {@link MemberCapShapeCode}:
 * - `"member-missing-sub-userid"` — `kind: "member"` requires `subUserId`.
 * - `"member-self"` — `subUserId === issUserId`.
 * - `"member-wildcard-collections"` — `"*"` in `scope.collections`.
 * - `"member-multi-collection"` — not exactly one collection.
 * - `"member-private-path"` — a path resolves into the issuer's
 *   `users/<issUserId>/` namespace.
 * - `"member-members-not-denied"` — an allow rule reaches `<col>/_members`
 *   with no sibling deny (read OR write — the directory is owner-only).
 * - `"member-keyring-not-denied"` — a write allow reaches `<col>/_keyring`
 *   with no sibling deny.
 *
 * Non-member caps pass through after the generic protocol checks.
 */
export function assertMemberCapShape(cert: UnsignedCapCert | CapCert): void {
  // Generic structural checks (iss/sub userId relations) stay in protocol.
  assertCapCertWellFormed(cert)
  if (cert.kind !== "member") return

  if (cert.subUserId === undefined) {
    throwCoded("member-missing-sub-userid", "kind=member requires subUserId")
  }
  if (cert.subUserId === cert.issUserId) {
    throwCoded("member-self", "kind=member cannot have subUserId === issUserId")
  }
  if (cert.scope.collections.includes("*")) {
    throwCoded(
      "member-wildcard-collections",
      "kind=member cannot use '*' in scope.collections",
    )
  }
  if (cert.scope.collections.length !== 1) {
    throwCoded(
      "member-multi-collection",
      "kind=member requires exactly one collection in scope.collections",
    )
  }
  assertScopeBarriers(cert, {
    privatePath: "member-private-path",
    membersNotDenied: "member-members-not-denied",
    keyringNotDenied: "member-keyring-not-denied",
  })
}

/**
 * Owner-namespace scope barriers shared by every subject-scoped cap kind
 * (`member` + `audience`). One source of truth for these security-critical
 * checks; the caller supplies the `.code` strings so each kind surfaces its own
 * reason over identical logic:
 *
 * - no scope path may resolve into the issuer's `users/<issUserId>/` namespace;
 * - any allow rule that matches `<col>/_members` requires a sibling deny;
 * - any **write** allow rule that matches `<col>/_keyring` requires a sibling deny.
 *
 * `{identity}` resolves to `issUserId` here (mint-time). This is intentionally
 * stricter than the resolver's subject substitution, so it can never create a
 * request-time escalation. Glob matching delegates to the protocol's
 * `pathGlobMatch` so mint barriers and request-path enforcement never drift.
 */
function assertScopeBarriers(
  cert: UnsignedCapCert | CapCert,
  codes: { privatePath: string; membersNotDenied: string; keyringNotDenied: string },
): void {
  const issUserId = cert.issUserId
  const issuerNsPrefix = `users/${issUserId}/`
  const issuerNsExact = `users/${issUserId}`
  if (cert.scope.paths) {
    for (const path of cert.scope.paths) {
      const resolved = path.split("{identity}").join(issUserId)
      if (resolved === issuerNsExact || resolved.startsWith(issuerNsPrefix)) {
        throwWithCode(codes.privatePath, `path '${path}' resolves to issuer's private namespace`)
      }
    }
  }
  // Compute resolved allows and denies once; reused by the `_members` and
  // `_keyring` rules below. A cap with NO `scope.paths` (or an empty list) is
  // path-UNRESTRICTED: `matchScopePath(_, undefined)` returns true at request
  // time, so it effectively allows every path with no deny — including the
  // owner-only `_members`/`_keyring`. Model that as an implicit `**` allow so
  // the barriers below fire (a subject-scoped member/audience cap must carry an
  // explicit path scope that denies those paths; only a device/root cap, which
  // does not go through these barriers, may be path-unrestricted).
  const pathUnrestricted = !cert.scope.paths || cert.scope.paths.length === 0
  const resolvedAllows: { raw: string; resolved: string }[] = []
  const resolvedDenies: string[] = []
  if (cert.scope.paths) {
    for (const entry of cert.scope.paths) {
      if (entry.startsWith("!")) {
        resolvedDenies.push(entry.slice(1).split("{identity}").join(issUserId))
      } else {
        resolvedAllows.push({
          raw: entry,
          resolved: entry.split("{identity}").join(issUserId),
        })
      }
    }
  }
  // `<col>/_members` is the owner-only directory. For every allow rule that
  // would match it, require a sibling deny — regardless of ops.
  for (const col of cert.scope.collections) {
    const membersPath = `${col}/_members`
    const matchingAllow = pathUnrestricted
      ? { raw: "**", resolved: "**" }
      : resolvedAllows.find((a) => pathGlobMatch(a.resolved, membersPath))
    if (!matchingAllow) continue
    const blockingDeny =
      !pathUnrestricted && resolvedDenies.some((d) => pathGlobMatch(d, membersPath))
    if (!blockingDeny) {
      throwWithCode(
        codes.membersNotDenied,
        `scope allows '${matchingAllow.raw}' to match '${membersPath}' without a '!${membersPath}' deny`,
      )
    }
  }
  // Caps with write authority must never grant write to any collection's
  // `_keyring` document.
  if (cert.scope.ops.includes("write")) {
    for (const col of cert.scope.collections) {
      const keyringPath = `${col}/_keyring`
      const matchingAllow = pathUnrestricted
        ? { raw: "**", resolved: "**" }
        : resolvedAllows.find((a) => pathGlobMatch(a.resolved, keyringPath))
      if (!matchingAllow) continue
      const blockingDeny =
        !pathUnrestricted && resolvedDenies.some((d) => pathGlobMatch(d, keyringPath))
      if (!blockingDeny) {
        throwWithCode(
          codes.keyringNotDenied,
          `write scope allows '${matchingAllow.raw}' to match '${keyringPath}' without a '!${keyringPath}' deny`,
        )
      }
    }
  }
}

/**
 * Mint an `audience` cap-cert: a public-link credential that binds **no** single
 * subject. Each redeemer signs requests with their own key (named via the
 * `X-Starfish-Pub` header); an optional `opts.audience` allow-list restricts who
 * may redeem, and its absence means any identity may. Carries no
 * `sub`/`subKem`/`subUserId` — those keys are deliberately omitted so the
 * canonical signing input stays deterministic across languages.
 *
 * `collection` is forced into `scope.collections` (single-collection by design).
 * `opts.expiresAt`/`opts.ttlSec` control expiry via the shared `resolveValidity`.
 *
 * Throws `Error` with `.code` of {@link AudienceCapShapeCode} for a malformed
 * scope, or the protocol's `audience-*` well-formedness codes for a bad `aud`.
 */
export async function mintAudienceCap(
  issEdPrivHex: string,
  issEdPubHex: string,
  collection: string,
  scope: ScopePreset,
  opts: AudienceMintOpts = {},
): Promise<CapCert> {
  const { nbf, exp } = resolveValidity(opts)
  const nonceBytes = opts.nonce ?? defaultNonce()
  const nonce = getBase64().encode(nonceBytes)
  const unsigned: UnsignedCapCert = {
    v: 1,
    kind: "audience",
    issAlg: opts.alg ?? DEFAULT_ALG,
    iss: issEdPubHex,
    issUserId: await userIdFromPubHex(issEdPubHex),
    scope: { ...scope, collections: [collection] },
    nbf,
    exp,
    nonce,
  }
  if (opts.audience !== undefined) {
    // An explicitly-empty list almost certainly means "restrict to nobody" by
    // mistake; silently dropping it would mint an OPEN link (any identity).
    // Reject it — callers who want an open link omit `audience` entirely.
    if (opts.audience.length === 0) {
      throwWithCode("audience-empty", "audience must be non-empty; omit it for an open link")
    }
    unsigned.aud = opts.audience
  }
  assertAudienceCapShape(unsigned)
  return signCapCert(unsigned, issEdPrivHex)
}

/**
 * Assert the structural shape of an `audience` cap-cert. Mirrors
 * {@link assertMemberCapShape} minus the single-subject rules (an audience cap
 * has no `sub`/`subUserId`); it keeps the single-collection and owner-namespace
 * barriers via {@link assertScopeBarriers}. Used by {@link mintAudienceCap}
 * (mint guard) and by `sharingServerPlugin` (server-side validation).
 *
 * Throws `Error` with `.code` set to one of {@link AudienceCapShapeCode}.
 * Non-audience caps pass through after the generic protocol checks.
 */
export function assertAudienceCapShape(cert: UnsignedCapCert | CapCert): void {
  assertCapCertWellFormed(cert)
  if (cert.kind !== "audience") return
  if (cert.scope.collections.includes("*")) {
    throwWithCode("audience-wildcard-collections", "kind=audience cannot use '*' in scope.collections")
  }
  if (cert.scope.collections.length !== 1) {
    throwWithCode("audience-multi-collection", "kind=audience requires exactly one collection in scope.collections")
  }
  assertScopeBarriers(cert, {
    privatePath: "audience-private-path",
    membersNotDenied: "audience-members-not-denied",
    keyringNotDenied: "audience-keyring-not-denied",
  })
}
