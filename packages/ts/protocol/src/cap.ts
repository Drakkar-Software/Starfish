/**
 * Capability Certificate (cap-cert) types and canonical encoding.
 *
 * v3.0 capability-based access control: the cap-cert is the bearer of
 * authority. Root principals sign one per device (proxy) or per member
 * (scoped grant). This module exports only the type definitions and the
 * canonical signing-input helper. Minting and signature verification are
 * implemented in higher-level packages.
 *
 * Starfish speaks a single signature suite on the wire (Ed25519 signing +
 * X25519 KEM). External roots (e.g. secp256k1/Nostr) bootstrap into a
 * Starfish identity via a derivation in `starfish-identities`; the resulting
 * identity is a normal Ed25519 identity from the wire's perspective.
 */

import { sha256 } from "@noble/hashes/sha2.js"
import { getBase64 } from "./platform.js"
import { stableStringify } from "./hash.js"
import * as ed25519Suite from "./suites/ed25519.js"
import { bytesToHex, hexToBytes } from "./suites/_hex.js"

/**
 * Authority binding kind.
 *
 * - `device`: subject acts as proxy for the issuer; URL `{identity}`
 *   resolves to `issUserId`.
 * - `member`: subject keeps their own identity; URL `{identity}` resolves
 *   to `subUserId`. The cap adds scoped roles only.
 * - `audience`: no single subject — the cap authorizes a *set* of identities
 *   (or any identity). It carries no `sub`/`subKem`/`subUserId`; instead each
 *   redeemer signs requests with their own key and names it via the
 *   `X-Starfish-Pub` header. An optional `aud` allow-list narrows who may
 *   redeem; when absent, any identity may. URL `{identity}` resolves to the
 *   presenter's own userId. Used by the public-link API in `starfish-sharing`.
 */
export type CapKind = "device" | "member" | "audience"

/**
 * Operations and resources a cap-cert authorizes.
 *
 * - `paths` entries are glob-style; entries prefixed with `!` are denylist
 *   rules (explicit deny beats wildcard allow). `paths` is optional.
 */
export type CapScope = {
  ops: ("read" | "write" | "list")[]
  collections: string[]
  paths?: string[]
}

/**
 * Capability certificate (signed).
 *
 * `kind: "device"` / `"member"` bind a single subject: `sub` (Ed25519 signing
 * pubkey) and `subKem` (X25519 KEM pubkey) are present. `subUserId` is
 * mandatory for `member`, optional for `device`.
 *
 * `kind: "audience"` binds **no** subject: `sub`, `subKem`, and `subUserId` are
 * **absent** and the optional `aud` allow-list is present instead. The absence
 * is load-bearing — the canonical signing input is a key-sorted stringify, so a
 * stray `sub`/`subKem` key (even `""`) would change the signed bytes and break
 * cross-language verification.
 */
export type CapCert = {
  v: 1
  kind: CapKind
  /** Issuer Ed25519 pubkey, hex (32 B). */
  iss: string
  /** `sha256(iss)[0:32]`, redundant but lets the server skip a hash. */
  issUserId: string
  /** Subject Ed25519 signing pubkey, hex (32 B). Absent for `audience`. */
  sub?: string
  /** Subject X25519 KEM pubkey, hex (32 B). Absent for `audience`. */
  subKem?: string
  /**
   * `sha256(sub)[0:32]`. Required for `kind: "member"`; optional for
   * `kind: "device"`; absent for `kind: "audience"`.
   */
  subUserId?: string
  scope: CapScope
  /**
   * Allow-list of subject Ed25519 pubkeys (64-char lowercase hex) for
   * `kind: "audience"`. When present it MUST be non-empty; when absent, any
   * identity may redeem. Forbidden on `device`/`member` caps.
   */
  aud?: string[]
  /** Not-before, unix seconds. */
  nbf: number
  /** Expiry, unix seconds. */
  exp: number
  /** Random nonce, base64-encoded (16 B). Supports revocation by nonce. */
  nonce: string
  /** Ed25519 signature over the canonical signing input, base64-encoded. */
  sig: string
}

/**
 * Cap-cert without its signature. This is the value whose canonical
 * stable-stringification is the Ed25519 signing input.
 */
export type UnsignedCapCert = Omit<CapCert, "sig">

/**
 * Resolve a subject cap-cert's **KEM recipient identity** — the X25519 pubkey
 * the keyring seals collection keys to. Throws for a subject-less (`audience`)
 * cap, which has no KEM recipient.
 */
export function recipientKem(cert: { sub?: string; subKem?: string }): { kemPubHex: string } {
  const kemPubHex = cert.subKem ?? cert.sub
  if (kemPubHex === undefined) {
    throw new Error("recipientKem: cap binds no subject KEM key (audience cap?)")
  }
  return { kemPubHex }
}

/**
 * True when `cert` is a self-signed device cap — the issuer is its own subject.
 *
 * This is the signature of a **root device**: `bootstrapRootIdentity` mints the
 * first device's cap with `iss === sub`, whereas every paired device is minted
 * by the root with `iss = root, sub = device` (`iss !== sub`), and member caps
 * always bind a distinct subject. Callers use it to distinguish the root device
 * from delegated devices/members (e.g. server-side root-only collections).
 *
 * Note: this only identifies a self-signed device cap; it does not by itself
 * prove the cap belongs to a *particular* root identity. Cross-identity
 * isolation comes from `issUserId` / `{identity}` path binding, not this check.
 */
export function isRootDeviceCap(cert: CapCert): boolean {
  return cert.kind === "device" && cert.iss === cert.sub
}

// ── Plugin contract (shared by server host + extension packages) ──────────────

/**
 * Validator for a specific cap-cert `kind`. Throws on failure; the server's
 * cap-resolver translates the throw into HTTP 401 with the thrown message.
 *
 * Defined here in the protocol package — the shared contract layer — so the
 * server host (`starfish-server`) and the extension packages
 * (`starfish-identities`, `starfish-sharing`) can both reference it without
 * a workspace dependency cycle.
 */
export type CapCertValidator = (cert: CapCert) => void

/**
 * Payload handed to a plugin's `afterWrite` hook after a successful push
 * (HTTP 200). Side-effect extensions (queue publishing, audit, webhooks,
 * change-data-capture) consume it without the server knowing their concern.
 */
export interface WriteEvent {
  /** Collection name the write targeted. */
  collection: string
  /** Content hash of the stored document, as returned to the client. */
  hash: string
  /** Server timestamp of the write, as returned to the client. */
  timestamp: number
  /** Route path parameters (e.g. `{ userId: "..." }`). */
  params: Record<string, string>
  /**
   * The pushed `data` object, when the collection is JSON and the request
   * body parsed to a plain object. Hooks decide whether to use it.
   */
  body?: Record<string, unknown>
  /** Namespace name when the write went through a named sub-router. */
  namespace?: string
  /**
   * The authenticated writer identity (`auth.identity`): the cap-bound userId of
   * the account that performed the write — `issUserId` for a device cap,
   * `subUserId` for a member cap, the presenter's derived userId for an audience
   * cap. Absent for an unauthenticated (public) write. Hooks that forward this
   * off-box (e.g. queue publishing) MUST gate it behind explicit config, since it
   * exposes *who* wrote — metadata the server otherwise never emits.
   */
  identity?: string
}

/**
 * Hook invoked once per registered plugin after a successful push. Runs in
 * plugin-list order. Failures are logged by the server, never propagated —
 * a hook outage must not break client writes.
 */
export type AfterWriteHook = (event: WriteEvent) => void | Promise<void>

/**
 * Context handed to a plugin's `beforePull` hook, before the local store is
 * read for a pull. Framework-neutral (no Hono/FastAPI types) so the contract
 * stays host-agnostic — mirrors {@link WriteEvent}.
 */
export interface PullHookContext {
  /** Collection name being pulled. */
  collection: string
  /** Resolved route path parameters (e.g. `{ userId: "..." }`). */
  params: Record<string, string>
  /** Namespace name when the pull went through a named sub-router. */
  namespace?: string
}

/**
 * Context handed to a plugin's `interceptPush` hook, before a push is written
 * locally. Carries the already-read raw request body so a hook can forward it
 * upstream (e.g. proxy the write to a primary).
 */
export interface PushHookContext {
  /** Collection name being pushed to. */
  collection: string
  /** Resolved route path parameters. */
  params: Record<string, string>
  /** Namespace name when the push went through a named sub-router. */
  namespace?: string
  /** Raw request body as received from the client. */
  rawBody: string
}

/**
 * Directive a `beforePull` hook returns. `proceed` lets the pull continue;
 * `reject` short-circuits with an HTTP error status + message.
 */
export type PullHookResult =
  | { action: "proceed" }
  | { action: "reject"; status: number; error: string }

/**
 * Directive an `interceptPush` hook returns. `proceed` lets the local write
 * continue; `reject` short-circuits with an HTTP error; `respond` short-
 * circuits with a full response body (e.g. a push proxied to a primary).
 */
export type PushHookResult =
  | { action: "proceed" }
  | { action: "reject"; status: number; error: string }
  | { action: "respond"; status: number; body: unknown }

/** Hook invoked before a pull is served. See {@link PullHookContext}. */
export type BeforePullHook = (
  ctx: PullHookContext,
) => PullHookResult | Promise<PullHookResult>

/** Hook invoked before a push is written locally. See {@link PushHookContext}. */
export type InterceptPushHook = (
  ctx: PushHookContext,
) => PushHookResult | Promise<PushHookResult>

/**
 * Directive an `interceptPull` hook returns. `proceed` lets the pull continue
 * normally; `respond` short-circuits the pull with a binary response body — the
 * host converts it to an HTTP response with the appropriate ETag / Cache-Control
 * headers.
 */
export type PullInterceptResult =
  | { action: "proceed" }
  | { action: "respond"; status: number; body: Uint8Array; contentType: string }

/**
 * Hook invoked before the JSON pull logic, after auth and the unsafe-key guard.
 * Lets an extension serve a binary document for a JSON-typed collection (e.g.
 * an events plugin that stores Parquet instead of JSON). Hosts call it for every
 * pulled collection; plugins filter by `ctx.collection`. Runs in plugin-list
 * order; the first `respond` wins. Additive.
 *
 * The hook receives a {@link PullHookContext} — `collection`, `params`,
 * `namespace` — which is sufficient to resolve the object-store key from the
 * plugin's configured storage-path template.
 */
export type InterceptPullHook = (
  ctx: PullHookContext,
) => PullInterceptResult | Promise<PullInterceptResult>

/**
 * Context handed to a plugin's `authorize` hook. Framework-neutral (no
 * Hono/FastAPI types). Unlike `beforePull`/`interceptPush`, this fires for
 * EVERY action (`pull`, `push`, `list`, including batch/bundle members), so an
 * extension can deny access by identity independent of roles — see
 * `@drakkar.software/starfish-restrictions`.
 */
export interface AuthorizeContext {
  /** The authenticated caller identity (`auth.identity`), or `undefined` for an
   *  anonymous (public) request. */
  identity?: string
  /** The action being authorized. */
  action: "pull" | "push" | "list"
  /** Collection name the action targets. */
  collection: string
  /** Namespace name when the request went through a named sub-router. */
  namespace?: string
  /** Resolved route path parameters (e.g. `{ userId: "..." }`). */
  params: Record<string, string>
  /** The caller's effective roles (post-enrichment), for context-aware policies. */
  roles: string[]
}

/**
 * Directive an `authorize` hook returns. `proceed` allows the action; `reject`
 * short-circuits with an HTTP error status + message (typically `403`).
 */
export type AuthorizeResult =
  | { action: "proceed" }
  | { action: "reject"; status: number; error: string }

/**
 * Hook invoked at the central authorization gate for every action, after roles
 * are resolved and the role-based check passes. Lets an extension deny access
 * (e.g. an identity deny/allow list). See {@link AuthorizeContext}.
 */
export type AuthorizeHook = (
  ctx: AuthorizeContext,
) => AuthorizeResult | Promise<AuthorizeResult>

/**
 * Server plugin: contributes per-kind cap-cert validators to the resolver
 * and/or write-path side-effect hooks. Apps compose the behaviors they want
 * by listing each extension's plugin.
 *
 * The runtime helpers that consume this contract (`composePluginValidators`,
 * `defaultServerPlugin`, the `afterWrite` dispatcher) live in
 * `starfish-server`; the type lives here so extensions can produce
 * `ServerPlugin` objects without importing the server.
 */
export interface ServerPlugin {
  /** Human-readable name. Used in error messages and audit logs. */
  name: string
  /**
   * Per-kind validators. The resolver dispatches by `cert.kind` to every
   * plugin that registered that kind, in plugin-list order; any throw
   * rejects the request.
   */
  capValidators?: Partial<Record<CapKind, CapCertValidator>>
  /**
   * Invoked after each successful push (HTTP 200). Additive — plugins that
   * only validate caps omit it. See {@link WriteEvent}.
   */
  afterWrite?: AfterWriteHook
  /**
   * Invoked before a pull is served, before the local store is read. Lets an
   * extension short-circuit the pull (e.g. reject a write-only collection) or
   * run a side effect first (e.g. a replica syncing from its primary). Hosts
   * call it for every pulled collection; plugins filter by `ctx.collection`.
   * Runs in plugin-list order; the first `reject` wins. Additive.
   */
  beforePull?: BeforePullHook
  /**
   * Invoked before a push is written locally. Lets an extension reject the
   * push or respond on its behalf (e.g. proxy the write to a primary). Hosts
   * call it for every pushed collection; plugins filter by `ctx.collection`.
   * Runs in plugin-list order; the first non-`proceed` result wins. Additive.
   */
  interceptPush?: InterceptPushHook
  /**
   * Invoked before the JSON pull logic, after auth and the unsafe-key guard.
   * Lets an extension serve a binary document for a JSON-typed collection.
   * Hosts call it for every pulled collection; plugins filter by
   * `ctx.collection`. Runs in plugin-list order; the first `respond` wins.
   * Additive. See {@link InterceptPullHook}.
   */
  interceptPull?: InterceptPullHook
  /**
   * Invoked at the central authorization gate for every action (`pull`,
   * `push`, `list`, incl. batch/bundle members), after roles are resolved and
   * the role-based check passes. Lets an extension deny access independent of
   * roles (e.g. an identity deny/allow list — see
   * `@drakkar.software/starfish-restrictions`). Runs in plugin-list order; the
   * first `reject` wins; a throw propagates. Additive.
   */
  authorize?: AuthorizeHook
  /**
   * Invoked during graceful shutdown so the plugin can release resources
   * (e.g. close a queue connection). Additive.
   */
  shutdown?: () => void | Promise<void>
}

/**
 * Domain-separation tag prepended to a cap-cert's signing input. Binds the
 * signature to the "cap-cert" message type *by construction*, so a signature
 * minted over one object type (a request signature, a revocation list) can never
 * be reinterpreted as a cap-cert even if a future field change made their
 * stable-stringified bodies overlap. The `\n` keeps the tag unambiguously
 * separated from the JSON that follows. Must stay byte-identical across TS,
 * Python, and the test-vector generators.
 */
const CAP_CERT_DOMAIN = "starfish-capcert-v1\n"

/**
 * Canonical UTF-8 string used as the Ed25519 signing input for a cap-cert:
 * the domain tag {@link CAP_CERT_DOMAIN} followed by `stableStringify` of the
 * cert with `sig` stripped — identical bytes across TypeScript and Python.
 *
 * Accepts a signed or unsigned cert and strips `sig` internally: the signing
 * input is over the *unsigned* cert, and `stableStringify` is key-sorted, so a
 * stray `sig` key would shift the byte stream and break verification. Mirrors
 * Python's `cap_cert_canonical_signing_input`, which strips `sig` the same way.
 */
export function capCertCanonicalSigningInput(cert: UnsignedCapCert | CapCert): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig: _sig, ...unsigned } = cert as CapCert
  return CAP_CERT_DOMAIN + stableStringify(unsigned as unknown as Record<string, unknown>)
}

// ── Signing & verification ────────────────────────────────────────────────────

/** Well-formedness assertion codes raised by `assertCapCertWellFormed`. */
export type CapCertWellFormedCode =
  | "malformed-shape"
  | "iss-userid-mismatch"
  | "sub-userid-mismatch"
  | "member-missing-sub-userid"
  | "member-self"
  | "member-wildcard-collections"
  | "member-multi-collection"
  | "member-private-path"
  | "member-members-not-denied"
  | "member-keyring-not-denied"
  | "audience-has-sub"
  | "non-audience-has-aud"
  | "audience-empty-aud"
  | "audience-aud-too-large"
  | "audience-aud-bad-entry"
  | "audience-aud-dup"

const VALID_OPS = new Set(["read", "write", "list"])

/** Required decoded length of a cap-cert `nonce` (matches the minted length). */
const NONCE_LEN_BYTES = 16

/** Upper bound on the number of entries in an audience cap's `aud` allow-list. */
const MAX_AUDIENCE = 64

/** An `aud` entry: a 64-char lowercase-hex Ed25519 pubkey. */
const AUD_ENTRY_RE = /^[0-9a-f]{64}$/

/** Aggregate result of `verifyCapCert`. */
export interface CapCertVerifyResult {
  ok: boolean
  reason?: string
}


/**
 * Derive a userId from an Ed25519 public key: `sha256(hexDecode(pubHex))[0:32]`
 * (the first 16 bytes, lowercase hex). The same derivation used for `issUserId`
 * / `subUserId`; exported so the server can bind an audience cap's presenter to
 * their own identity (`auth.identity = userIdFromPubHex(presenterPubHex)`).
 */
export function userIdFromPubHex(pubHex: string): string {
  const pubBytes = hexToBytes(pubHex)
  const digest = sha256(pubBytes)
  return bytesToHex(digest).slice(0, 32)
}

function throwCoded(code: CapCertWellFormedCode, message: string): never {
  const err = new Error(message) as Error & { code: CapCertWellFormedCode }
  err.code = code
  throw err
}

/**
 * Glob match used for cap-cert path semantics. `**` matches any run of
 * characters including slashes; a single `*` matches any run of non-slash
 * characters; every other character matches literally. The pattern must match
 * the entire `target`.
 *
 * The `**` rule is mandatory for correctness, not convenience: the server's
 * request-path enforcement (`matchScopePath`) treats `**` as crossing
 * slashes, so the member-cap scope barriers that decide whether a `_keyring`
 * or `_members` deny is required must use the identical rule. A matcher that
 * stopped `**` at a slash would clear a cap the resolver later grants — which
 * is exactly the gap this rule closes. `matchScopePath` delegates here so the
 * two can never drift apart again.
 *
 * Exported so extension packages that own kind-specific scope rules (e.g.
 * `starfish-sharing`'s member-cap shape checks) can reuse the exact same
 * matcher the protocol uses.
 */
export function pathGlobMatch(glob: string, target: string): boolean {
  // Linear two-pointer matcher. A regex compiled from an attacker-controlled
  // glob (`*`->`[^/]*`, `**`->`.*`) backtracks super-polynomially on a crafted
  // non-match, and this runs on the auth hot path for every request, so it is a
  // ReDoS sink. This matcher is O(len(glob) * len(target)) with no backtracking
  // explosion. `**` matches any run of characters (incl. `/` and line
  // terminators); `*` matches any run of non-`/` characters. Kept byte-for-byte
  // identical to the Python `path_glob_match`.
  // Tokens: 2 = `**`, 1 = `*`, otherwise a literal character.
  const toks: Array<{ star: 0 | 1 | 2; c: string }> = []
  for (let i = 0; i < glob.length; ) {
    if (glob[i] === "*" && glob[i + 1] === "*") {
      toks.push({ star: 2, c: "" })
      i += 2
    } else if (glob[i] === "*") {
      toks.push({ star: 1, c: "" })
      i += 1
    } else {
      toks.push({ star: 0, c: glob[i]! })
      i += 1
    }
  }

  let si = 0 // index into target
  let ti = 0 // index into toks
  let starTi = -1 // token index of the most recent star we can backtrack to
  let starType: 1 | 2 = 1
  let starMatch = 0 // target index the star began matching at
  while (si < target.length) {
    if (ti < toks.length && toks[ti]!.star === 0 && toks[ti]!.c === target[si]) {
      si += 1
      ti += 1
    } else if (ti < toks.length && toks[ti]!.star !== 0) {
      starTi = ti
      starType = toks[ti]!.star as 1 | 2
      starMatch = si
      ti += 1
    } else if (starTi !== -1) {
      // Extend the previous star by one target character. A single `*` may not
      // absorb a `/`; `**` absorbs anything.
      if (starType === 1 && target[starMatch] === "/") return false
      starMatch += 1
      si = starMatch
      ti = starTi + 1
    } else {
      return false
    }
  }
  while (ti < toks.length && toks[ti]!.star !== 0) ti += 1
  return ti === toks.length
}

/**
 * Generic, kind-agnostic cap-cert structural checks. Throws on the first
 * failure with `Error.code` set to one of the codes in
 * {@link CapCertWellFormedCode}.
 *
 * Rules (apply to every cap kind):
 * - `sha256(hexDecode(iss))[0:32]` must equal `issUserId`.
 * - If `subUserId` is present, `sha256(hexDecode(sub))[0:32]` must equal it.
 *
 * Kind-specific structural rules (e.g. the member-cap barriers:
 * `member-self`, `member-private-path`, `member-members-not-denied`, …) are
 * owned by the extension that defines that kind — see
 * `assertMemberCapShape` in `@drakkar.software/starfish-sharing`. The server
 * enforces them through the extension's `ServerPlugin` validator; with
 * strict-kind dispatch a cap whose kind has no registered validator is
 * rejected outright.
 */
export function assertCapCertWellFormed(cert: UnsignedCapCert | CapCert): void {
  // Runtime shape validation of attacker-supplied fields. A cap-cert arrives as
  // parsed JSON with no type guarantees, and the resolver feeds `scope.ops` /
  // `scope.collections` straight into role synthesis — a string `scope.ops`
  // would be iterated character-by-character into fabricated roles instead of
  // failing closed. Validate the structure before any field is trusted.
  const c = cert as unknown as Record<string, unknown>
  if (c.kind !== "device" && c.kind !== "member" && c.kind !== "audience") {
    throwCoded("malformed-shape", 'cap-cert kind must be "device", "member", or "audience"')
  }
  const isAudience = c.kind === "audience"
  if (
    typeof c.iss !== "string" ||
    typeof c.issUserId !== "string" ||
    typeof c.nonce !== "string"
  ) {
    throwCoded("malformed-shape", "cap-cert iss/issUserId/nonce must be strings")
  }
  // Subject binding is kind-specific. An audience cap binds no subject, so
  // `sub`/`subKem`/`subUserId` MUST all be absent (present is rejected to keep
  // the canonical signing input deterministic). Device/member caps carry a
  // subject: `sub` (Ed25519 signing pubkey) and `subKem` (X25519 KEM pubkey)
  // are both required.
  if (isAudience) {
    if (c.sub !== undefined || c.subKem !== undefined || c.subUserId !== undefined) {
      throwCoded("audience-has-sub", "audience cap must not carry sub/subKem/subUserId")
    }
  } else {
    if (typeof c.sub !== "string") {
      throwCoded("malformed-shape", "cap-cert sub must be a string")
    }
    if (typeof c.subKem !== "string") {
      throwCoded("malformed-shape", "cap-cert subKem must be a string")
    }
  }
  // `Number.isInteger` (not `typeof === "number"`) so `Infinity`/`NaN` are
  // rejected: a wire `exp: 1e400` parses to `Infinity`, which would pass the
  // `now > exp + skew` expiry gate (effectively disabling expiry). It accepts a
  // whole-number float (`1700000000.0`) because JSON parsing collapses that to
  // the same IEEE-754 value as the integer; Python's `_is_js_integer` matches
  // this exactly, so the two stay in agreement (a fractional float is rejected
  // on both sides).
  if (!Number.isInteger(c.nbf) || !Number.isInteger(c.exp)) {
    throwCoded("malformed-shape", "cap-cert nbf/exp must be integers")
  }
  if (c.subUserId !== undefined && typeof c.subUserId !== "string") {
    throwCoded("malformed-shape", "cap-cert subUserId must be a string when present")
  }
  // Nonce must be standard base64 of exactly 16 bytes (the minted length).
  // Validated only as a string before, a self-issuer could mint caps sharing a
  // nonce or use a degenerate/empty one — weakening per-cap revocation (which
  // keys on the nonce) and the per-signature uniqueness it provides.
  let nonceBytes: Uint8Array
  try {
    nonceBytes = getBase64().decode(c.nonce as string)
  } catch {
    throwCoded("malformed-shape", "cap-cert nonce must be base64")
  }
  if (nonceBytes.length !== NONCE_LEN_BYTES) {
    throwCoded("malformed-shape", `cap-cert nonce must decode to ${NONCE_LEN_BYTES} bytes`)
  }
  const scope = c.scope as Record<string, unknown> | null | undefined
  if (typeof scope !== "object" || scope === null) {
    throwCoded("malformed-shape", "cap-cert scope must be an object")
  }
  if (
    !Array.isArray(scope.ops) ||
    scope.ops.some((op) => typeof op !== "string" || !VALID_OPS.has(op))
  ) {
    throwCoded("malformed-shape", "cap-cert scope.ops must be an array of read|write|list")
  }
  if (
    !Array.isArray(scope.collections) ||
    scope.collections.some((col) => typeof col !== "string")
  ) {
    throwCoded("malformed-shape", "cap-cert scope.collections must be an array of strings")
  }
  if (
    scope.paths !== undefined &&
    (!Array.isArray(scope.paths) || scope.paths.some((p) => typeof p !== "string"))
  ) {
    throwCoded("malformed-shape", "cap-cert scope.paths must be an array of strings when present")
  }

  // `aud` allow-list: valid only on an audience cap, optional, and when present
  // a non-empty, bounded, de-duplicated list of 64-char lowercase-hex pubkeys.
  // Its absence is the canonical encoding of "any identity may redeem".
  if (isAudience) {
    if (c.aud !== undefined) assertAudList(c.aud)
  } else if (c.aud !== undefined) {
    throwCoded("non-audience-has-aud", "aud is only valid on an audience cap")
  }

  // iss must hash to issUserId
  if (userIdFromPubHex(cert.iss) !== cert.issUserId) {
    throwCoded("iss-userid-mismatch", "issUserId does not match sha256(iss)[0:32]")
  }

  // sub must hash to subUserId when subUserId is present (device/member only;
  // an audience cap has neither, so this is skipped). The `typeof` guard both
  // narrows `cert.sub` to a string for the hash call and never fires for valid
  // device/member input (sub was already checked above).
  if (cert.subUserId !== undefined) {
    if (typeof cert.sub !== "string" || userIdFromPubHex(cert.sub) !== cert.subUserId) {
      throwCoded("sub-userid-mismatch", "subUserId does not match sha256(sub)[0:32]")
    }
  }
}

/**
 * Validate an audience cap's `aud` allow-list. Throws a coded
 * {@link CapCertWellFormedCode} on the first failure. Kept identical to
 * Python's `_assert_aud_list` so the two languages reject the exact same lists.
 */
function assertAudList(aud: unknown): void {
  if (!Array.isArray(aud)) {
    throwCoded("audience-aud-bad-entry", "aud must be an array of hex pubkeys")
  }
  if (aud.length === 0) {
    throwCoded("audience-empty-aud", "aud must be non-empty when present")
  }
  if (aud.length > MAX_AUDIENCE) {
    throwCoded("audience-aud-too-large", `aud must have at most ${MAX_AUDIENCE} entries`)
  }
  for (const entry of aud) {
    if (typeof entry !== "string" || !AUD_ENTRY_RE.test(entry)) {
      throwCoded("audience-aud-bad-entry", "aud entries must be 64-char lowercase-hex pubkeys")
    }
  }
  if (new Set(aud).size !== aud.length) {
    throwCoded("audience-aud-dup", "aud must not contain duplicate entries")
  }
}

/**
 * Sign an unsigned cap-cert with the issuer's Ed25519 private key.
 *
 * @param cert Unsigned cap-cert.
 * @param issPrivHex Issuer 32-byte Ed25519 seed, hex.
 * @returns The signed cap-cert with `sig` populated (base64 standard, padded).
 */
export function signCapCert(cert: UnsignedCapCert, issPrivHex: string): CapCert {
  const message = new TextEncoder().encode(capCertCanonicalSigningInput(cert))
  const sigBytes = ed25519Suite.sign(message, issPrivHex)
  const sig = getBase64().encode(sigBytes)
  return { ...cert, sig }
}

/**
 * Verify the Ed25519 signature on a cap-cert. Returns `true` iff `cert.sig`
 * verifies against `cert.iss` and the canonical signing input.
 *
 * This function checks only the signature; use {@link verifyCapCert} to
 * also check the not-before / expiry window and well-formedness.
 */
export function verifyCapCertSignature(cert: CapCert): boolean {
  try {
    // `capCertCanonicalSigningInput` strips `sig` itself, so the signed cert can
    // be passed directly — the signing input is over the unsigned cert.
    const message = new TextEncoder().encode(capCertCanonicalSigningInput(cert))
    const sigBytes = getBase64().decode(cert.sig)
    return ed25519Suite.verify(sigBytes, message, cert.iss)
  } catch {
    return false
  }
}

/**
 * Orchestrated verification: signature + not-before/expiry window
 * (with `clockSkewSec` slop, default 300s) + well-formedness checks.
 *
 * Returns `{ ok: true }` when every check passes; `{ ok: false, reason }`
 * with a short machine-readable reason otherwise.
 */
export async function verifyCapCert(
  cert: CapCert,
  opts: { now: number; clockSkewSec?: number },
): Promise<CapCertVerifyResult> {
  const skew = opts.clockSkewSec ?? 300
  // Well-formedness FIRST (includes runtime shape validation) so the time-window
  // comparisons below never run against a non-numeric `nbf`/`exp` — a malformed
  // cert fails closed with a structural reason instead of slipping through.
  try {
    assertCapCertWellFormed(cert)
  } catch (e) {
    const code = (e as Error & { code?: string }).code
    return { ok: false, reason: code ?? "malformed" }
  }
  // Reject an inverted (or zero-width) validity window before the time gates.
  // Without this, a cert whose `exp` is at or before `nbf` could still pass both
  // `now < nbf - skew` and `now > exp + skew` during the instant where the skew
  // margins overlap (`nbf - exp <= 2*skew`). `exp` must be strictly after `nbf`.
  if (cert.exp <= cert.nbf) return { ok: false, reason: "inverted-window" }
  // Time window
  if (opts.now < cert.nbf - skew) return { ok: false, reason: "not-yet-valid" }
  if (opts.now > cert.exp + skew) return { ok: false, reason: "expired" }
  // Signature
  const sigOk = await verifyCapCertSignature(cert)
  if (!sigOk) return { ok: false, reason: "bad-signature" }
  return { ok: true }
}
