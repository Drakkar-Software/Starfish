/**
 * Device-code space-join pairing over ONE public rendezvous slot.
 *
 * A requester (typically a website, holding no wallet and no `Session`)
 * generates ephemeral device keys, proves possession of them, and publishes a
 * short human-typeable code. A human reads that code off the requester's
 * screen and types it into an approving app that DOES hold a `Session`. The
 * approver looks the code up, shows `origin`/`label` for a human decision,
 * and — only if approved — calls `inviteToSpace` and seals the resulting
 * `{spaceId, cap}` to the requester's ephemeral KEM key. The requester unseals
 * it with a private key that never left its process.
 *
 * ## One slot, two phases
 *
 * Both halves of the exchange live at the SAME storage path, keyed by `code`
 * alone ({@link SpaceLayout.joinSessionPull} / `joinSessionPush`, default
 * `_pairing/session/{code}`). The document is a discriminated union on
 * `phase`:
 *
 *  - `phase: "request"` — written **create-only** (`baseHash: null`), so only
 *    the first write to a fresh code's slot succeeds.
 *  - `phase: "grant"` — written as a **CAS update** against the hash of the
 *    request document the approver just read. A racing writer needs that same
 *    hash, so a bogus grant surfaces as a `ConflictError`, never a silent
 *    overwrite.
 *
 * `code` is therefore the single address for the whole exchange. It is also
 * bound into the crypto twice: it is the PoP signing input (so a signature
 * cannot be replayed under a different code) and the seal AAD (so a grant
 * ciphertext copied into a different code's slot fails to open).
 *
 * ## Why KEM-sealing and not PIN-sealing
 *
 * {@link startDevicePairing} in `pairing.ts` pairs a person's OWN two devices
 * and can PIN-seal because it has two independent out-of-band channels (a
 * scanned QR *and* a separately-known PIN). This flow has exactly one channel
 * (read a code, type a code), so confidentiality rests on the requester's
 * ephemeral KEM private key, not on the guessability of the code. That is also
 * why the grant slot is **not** auto-cleared after a successful read the way
 * `completeDevicePairing` clears its slot: a live pairing is legitimately
 * re-polled over its lifetime. Use {@link clearSpaceJoinGrant} explicitly at
 * unpair time; the collection's TTL is the outer backstop.
 */
import { generateDeviceKeys, type GeneratedDeviceKeys } from "@drakkar.software/starfish-identities"
import { ed25519Suite } from "@drakkar.software/starfish-protocol"
import { seal, unseal, bytesToHex, hexToBytes } from "@drakkar.software/starfish-keyring"
import type { SealedBlob, SealerKeys } from "@drakkar.software/starfish-keyring"
import { StarfishHttpError } from "@drakkar.software/starfish-client"
import type { StarfishClient } from "@drakkar.software/starfish-client"

import { makeAnonSpaceClient } from "./client.js"
import { runCas } from "./cas-retry.js"
import type { SpaceLayout } from "./config.js"
import { getSpacesConfig } from "./config.js"
import { defaultSpaceLayout, defaultUserIdFromEdPub } from "./layout.js"
import { signKemSig } from "./request-verify.js"
import type { JoinRequest } from "./token-types.js"

// ── Code generation ────────────────────────────────────────────────────────────

/** Excludes visually-ambiguous characters (0/O, 1/I/L) — Crockford-style,
 *  meant to be read off one screen and typed on another. 31 symbols
 *  (23 letters + 8 digits), 8 characters ⇒ 8·log2(31) ≈ 39.63 bits of
 *  entropy, well above RFC 8628's device-flow `user_code` minimum, and
 *  bounded further by the rendezvous collection's TTL and per-IP rate limit
 *  (not something this package controls). {@link randomCode} uses rejection
 *  sampling (see `CODE_REJECT_THRESHOLD`) so this figure is the real, uniform
 *  entropy — not a biased approximation of it. */
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
const CODE_LENGTH = 8
// 256 is not a multiple of CODE_ALPHABET.length (31) — a plain `byte %
// length` would over-represent the first `256 % 31 = 8` symbols (A-H) by
// 12.5% in every character position. Reject any byte at or above the largest
// multiple of the alphabet length that still fits in a byte
// (Math.floor(256 / 31) * 31 = 248) and draw a replacement — the remaining
// range [0, 248) maps onto the 31 symbols with exactly uniform probability.
const CODE_REJECT_THRESHOLD = Math.floor(256 / CODE_ALPHABET.length) * CODE_ALPHABET.length

const DEFAULT_REQUEST_TTL_SEC = 5 * 60
// `expiresAt`/`createdAt` are NOT covered by popSig — anyone with the code can
// rewrite them, and the ONLY thing that kept the code's live window actually
// short was a default nobody was forced to respect. This is the real
// enforcement: a request whose declared window exceeds it is rejected outright
// by parseSpaceJoinRequest, and createSpaceJoinRequest clamps its own ttlSec to
// it too so a well-meaning caller can't accidentally create something this
// module would reject anyway.
const MAX_REQUEST_TTL_SEC = 60 * 60

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

function randomCode(): string {
  const chars: string[] = []
  // Pull a batch at a time (rather than one byte per iteration) so a run of
  // rejected bytes doesn't turn into a syscall-per-byte loop — rejection hits
  // ~3% of bytes, so a fresh CODE_LENGTH-sized batch almost always finishes
  // the code outright, with a further batch only on the rare tail.
  while (chars.length < CODE_LENGTH) {
    const batch = randomBytes(CODE_LENGTH)
    for (const b of batch) {
      if (b >= CODE_REJECT_THRESHOLD) continue
      chars.push(CODE_ALPHABET[b % CODE_ALPHABET.length])
      if (chars.length === CODE_LENGTH) break
    }
  }
  return chars.join("")
}

/** What binds `code`/`devEdPub`/`devKemPub` together and proves the requester
 *  holds `devEdPriv` — without this, a request record's public keys could be
 *  swapped in transit with no way to detect it. Signed over a canonical JSON
 *  of the three fields so a signature can't be replayed under a different
 *  (key-pair, code) combination. `code` — not a separate session id — is the
 *  binding term: it is the slot address, so a request document relocated to
 *  another code's slot no longer verifies. */
function popSigningInput(code: string, devEdPub: string, devKemPub: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ code, devEdPub, devKemPub }))
}

// ── Document shapes ────────────────────────────────────────────────────────────

/** Sync-server coordinates for the public rendezvous collection. */
export interface SpaceJoinRendezvous {
  baseUrl: string
  namespace: string
}

/**
 * The `phase: "request"` half of the join-session document.
 *
 * Deliberately carries NO rendezvous coordinates: the approving side must use
 * its OWN trusted server config (the one it used to look the code up), never a
 * value read out of a document any anonymous party can write — otherwise a
 * hostile "requester" could point the approver's outbound writes at a host of
 * its choosing. It also carries no `code`: the code IS the address, and
 * duplicating it in the body would only create a second, tamperable copy.
 */
export interface SpaceJoinRequestPayload {
  v: 1
  phase: "request"
  devEdPub: string
  devKemPub: string
  /** `ed25519Suite.sign(popSigningInput(code, devEdPub, devKemPub), devEdPriv)`,
   *  hex. Proves the requester holds `devEdPriv` — not proof of the requester's
   *  identity or intent, which is exactly why `origin` is still what the
   *  approving human relies on. */
  popSig: string
  /** `signKemSig({kemPub: devKemPub, edPriv: devEdPriv})`, hex — a SEPARATE
   *  proof-of-possession signature over just `devKemPub`, matching the
   *  `{edPub, kemPub, userId, kemSig}` join-request shape `parseJoinRequest` /
   *  `inviteToSpace` expect. {@link joinRequestFromSpaceJoinRequest}
   *  reassembles that shape from this plus the two public keys above, so the
   *  requester never needs a full `Session` just to call `makeJoinRequest()`
   *  for an identity it has no wallet to derive. */
  joinRequestKemSig: string
  /** Attacker-controlled in the sense that anyone can put any string here —
   *  the approving side must verify it (e.g. a `.well-known` fetch), not trust
   *  it at face value. */
  origin: string
  label?: string
  /** Opaque to this module: whatever the approving app wants to show a human
   *  about what is being asked for. Validated only as a string array. */
  requestedScopes?: string[]
  createdAt: string
  expiresAt: string
}

/** The `phase: "grant"` half — same document, same slot, after approval. */
export interface SpaceJoinGrantPayload {
  v: 1
  phase: "grant"
  /** `{spaceId, cap}` sealed to the request's `devKemPub`, AAD = `code`. */
  sealed: SealedBlob
  grantedAt: string
}

/** The single discriminated-union document living at `joinSessionPull(code)`. */
export type SpaceJoinSessionDoc = SpaceJoinRequestPayload | SpaceJoinGrantPayload

const GRANT_ENVELOPE_KIND = "starfish-space-join-grant"
const GRANT_ENVELOPE_VERSION = 1

interface GrantEnvelope {
  v: typeof GRANT_ENVELOPE_VERSION
  kind: typeof GRANT_ENVELOPE_KIND
  spaceId: string
  cap: unknown
}

/**
 * Thrown by {@link fetchSpaceJoinGrant} when the slot HAS advanced to
 * `phase: "grant"` but the grant itself doesn't check out — a malformed
 * sealed blob, a malformed envelope, or `unseal` rejecting it (wrong AAD /
 * relocated, wrong recipient, wrong sealer, tampered ciphertext). Distinct
 * from every other error this module can throw (transport errors, transient
 * server errors) so {@link awaitSpaceJoinGrant} can fail fast on a real
 * integrity signal instead of treating it like "not approved yet" and
 * polling it all the way to the timeout.
 */
export class SpaceJoinGrantIntegrityError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = "SpaceJoinGrantIntegrityError"
  }
}

// ── Create (pure) ──────────────────────────────────────────────────────────────

/** Options for {@link createSpaceJoinRequest}. */
export interface CreateSpaceJoinRequestOptions {
  /** The requester's own origin, shown to the approving human. */
  origin: string
  label?: string
  requestedScopes?: string[]
  /** Clamped to one hour — see `MAX_REQUEST_TTL_SEC`. Default: 5 minutes. */
  ttlSec?: number
}

/**
 * Create a join request: fresh ephemeral device keys (never the caller's own
 * identity), a proof-of-possession signature, and a short human code. Pure —
 * no I/O; {@link startSpaceJoinRequest} is the publishing wrapper.
 *
 * Returns `code` and `device` separately from `request` since the caller needs
 * the code to display and the private device keys to unseal the eventual
 * grant — neither travels in `request` itself except in already-public form
 * (`devEdPub`/`devKemPub`, not the private halves).
 */
export function createSpaceJoinRequest(opts: CreateSpaceJoinRequestOptions): {
  request: SpaceJoinRequestPayload
  device: GeneratedDeviceKeys
  code: string
} {
  const device = generateDeviceKeys()
  const code = randomCode()
  // Clamped, not just defaulted — a caller passing an oversized ttlSec would
  // otherwise create a request parseSpaceJoinRequest rejects outright (see
  // MAX_REQUEST_TTL_SEC), silently breaking their own integration instead of
  // getting the longest window this module will accept. Does NOT clamp a
  // NEGATIVE ttlSec (e.g. for testing an already-expired request) — only the
  // upper bound is enforced here.
  const ttlSec = Math.min(opts.ttlSec ?? DEFAULT_REQUEST_TTL_SEC, MAX_REQUEST_TTL_SEC)
  const now = new Date()
  const popSig = bytesToHex(
    ed25519Suite.sign(popSigningInput(code, device.edPub, device.kemPub), device.edPriv),
  )
  const joinRequestKemSig = signKemSig({ kemPub: device.kemPub, edPriv: device.edPriv })

  const request: SpaceJoinRequestPayload = {
    v: 1,
    phase: "request",
    devEdPub: device.edPub,
    devKemPub: device.kemPub,
    popSig,
    joinRequestKemSig,
    origin: opts.origin,
    ...(opts.label ? { label: opts.label } : {}),
    ...(opts.requestedScopes ? { requestedScopes: opts.requestedScopes } : {}),
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlSec * 1000).toISOString(),
  }
  return { request, device, code }
}

// ── Parse / validate ───────────────────────────────────────────────────────────

// Ed25519/X25519 public keys are 32 raw bytes; an Ed25519 signature is 64 —
// hex-encoded, that's exactly these lengths. Checked BEFORE hexToBytes is
// called on any of them: hexToBytes allocates proportionally to input length
// with no ceiling of its own, so an unbounded hex string here would allocate
// before ever reaching signature verification.
const HEX_KEY_LENGTH = 64
const HEX_SIG_LENGTH = 128
const MAX_ORIGIN_LENGTH = 2048
const MAX_LABEL_LENGTH = 200
// C0/C1 control characters (including \n, \r — a native <Text> renders an
// embedded newline as a real line break, letting attacker text masquerade as
// extra app chrome) plus the Unicode bidi override/isolate controls
// (U+202A-E, U+2066-9) that can visually reverse or reorder a rendered string
// — e.g. making a hostile host read as a different one. Written as explicit
// \u escapes, never literal control/bidi characters in source.
const UNSAFE_TEXT_PATTERN = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/

function assertBoundedSafeText(value: string, field: string, maxLength: number): void {
  if (value.length > maxLength) throw new Error(`space join request: ${field} exceeds max length`)
  if (UNSAFE_TEXT_PATTERN.test(value)) {
    throw new Error(`space join request: ${field} contains a disallowed control or bidi-override character`)
  }
}

function assertHexLength(value: string, field: string, expectedLength: number): void {
  if (value.length !== expectedLength || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`space join request: ${field} is not a valid ${expectedLength}-character hex string`)
  }
}

/**
 * Parse and validate a join-request document fetched by code. Verifies the
 * proof-of-possession signature against `code` and rejects an expired
 * request — both before the approving side does anything else with it.
 *
 * `code` is a REQUIRED second argument, not a field of `payload`: it is the
 * slot address the document was read from, and binding the signature to it is
 * what makes a request document non-relocatable. Passing the address in (as
 * opposed to trusting a copy inside the body) is the whole check.
 *
 * Does NOT verify `origin` resolves to anything real; that needs an actual
 * network check the approving side performs itself (this function stays
 * I/O-free). It DOES bound and sanity-check `origin`/`label` as strings — a
 * length cap, a URL parse for `origin`, and rejecting control/bidi-override
 * characters in both — since they're the two fields an approving human
 * actually reads and relies on. Full homoglyph/IDNA-confusable host detection
 * is out of scope, the same judgment call already made for origin verification
 * itself.
 */
export function parseSpaceJoinRequest(payload: string, code: string): SpaceJoinRequestPayload {
  let parsed: unknown
  try {
    parsed = JSON.parse(payload)
  } catch {
    throw new Error("not valid JSON")
  }
  if (typeof parsed !== "object" || parsed === null) throw new Error("not an object")
  const p = parsed as Record<string, unknown>
  if (p.v !== 1 || p.phase !== "request") throw new Error("not a space join request payload")
  if (
    typeof p.devEdPub !== "string" || typeof p.devKemPub !== "string" || typeof p.popSig !== "string"
    || typeof p.joinRequestKemSig !== "string" || typeof p.origin !== "string"
    || typeof p.createdAt !== "string" || typeof p.expiresAt !== "string"
  ) {
    throw new Error("malformed space join request payload")
  }
  if (p.label !== undefined && typeof p.label !== "string") {
    throw new Error("malformed space join request payload: label")
  }
  if (
    p.requestedScopes !== undefined
    && (!Array.isArray(p.requestedScopes) || p.requestedScopes.some((s) => typeof s !== "string"))
  ) {
    throw new Error("malformed space join request payload: requestedScopes")
  }

  assertHexLength(p.devEdPub, "devEdPub", HEX_KEY_LENGTH)
  assertHexLength(p.devKemPub, "devKemPub", HEX_KEY_LENGTH)
  assertHexLength(p.popSig, "popSig", HEX_SIG_LENGTH)
  assertHexLength(p.joinRequestKemSig, "joinRequestKemSig", HEX_SIG_LENGTH)
  assertBoundedSafeText(p.origin, "origin", MAX_ORIGIN_LENGTH)
  if (p.label !== undefined) assertBoundedSafeText(p.label as string, "label", MAX_LABEL_LENGTH)
  try {
    new URL(p.origin)
  } catch {
    throw new Error("space join request: origin is not a valid URL")
  }

  const request = p as unknown as SpaceJoinRequestPayload

  const verified = ed25519Suite.verify(
    hexToBytes(request.popSig),
    popSigningInput(code, request.devEdPub, request.devKemPub),
    request.devEdPub,
  )
  if (!verified) throw new Error("space join request: invalid proof-of-possession signature")

  // Date.parse of a malformed string returns NaN, and every comparison against
  // NaN is false — so a garbage expiresAt would otherwise be silently treated
  // as "not expired" instead of rejected. Fail closed.
  const expiresAtMs = Date.parse(request.expiresAt)
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) throw new Error("space join request: expired")

  // The actual enforcement of "short-lived code" — expiresAt/createdAt are NOT
  // covered by popSig, so a party with the code can rewrite either to anything.
  // Comparing expiresAt against the request's OWN createdAt would be trivially
  // bypassable: an attacker controlling both fields can place them arbitrarily
  // far in the future while keeping their difference inside the cap, making the
  // code "look" freshly issued no matter when it's actually redeemed (e.g.
  // createdAt = now+364d, expiresAt = now+364d+1h — passes a createdAt-relative
  // check, but the code stays "valid" for the next year). Anchoring to THIS
  // CALL's real wall clock instead closes that: a request cannot claim to remain
  // valid more than MAX_REQUEST_TTL_SEC from right now, independent of what it
  // claims createdAt to be. createdAt itself is otherwise purely informational —
  // never used for any security decision here.
  if (expiresAtMs - Date.now() > MAX_REQUEST_TTL_SEC * 1000) {
    throw new Error("space join request: expiry window exceeds the maximum this module allows")
  }

  return request
}

// ── Transport helpers ──────────────────────────────────────────────────────────

function anonClient(rendezvous: SpaceJoinRendezvous, fetchFn?: typeof globalThis.fetch): StarfishClient {
  return makeAnonSpaceClient({ baseUrl: rendezvous.baseUrl, namespace: rendezvous.namespace, fetch: fetchFn })
}

interface JoinSessionDocResult {
  data: Record<string, unknown>
  hash: string
}

/**
 * Pull the join-session slot. Returns `null` ONLY for "nothing published
 * there" — either a 404 or an empty/absent document body (an unwritten
 * collection document can pull as `null`, the string `"null"`, or `{}`
 * depending on the deployment). Every OTHER failure (transport, 5xx, 403)
 * propagates, so a caller polling in a loop can tell "not approved yet" apart
 * from "the server is unreachable".
 */
async function pullJoinSession(client: StarfishClient, path: string): Promise<JoinSessionDocResult | null> {
  const result = await client.pull(path).catch((err: unknown) => {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  })
  if (!result) return null
  const raw: unknown = result.data
  let parsed: unknown = raw
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw)
    } catch {
      return null
    }
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) return null
  if (Object.keys(parsed).length === 0) return null
  return { data: parsed as Record<string, unknown>, hash: result.hash ?? "" }
}

// ── Request side (session-less resolvable) ─────────────────────────────────────

/** Options for {@link startSpaceJoinRequest}. */
export interface StartSpaceJoinRequestOptions extends CreateSpaceJoinRequestOptions {
  /** Sync-server coordinates for the public rendezvous collection. */
  rendezvous: SpaceJoinRendezvous
  /** Path layout for the rendezvous slot. Default: {@link defaultSpaceLayout}. */
  layout?: SpaceLayout
  /** Optional fetch override (e.g. a timeout wrapper) for the anon client. */
  fetch?: typeof globalThis.fetch
}

/**
 * The requester's own end of a device-code space join: its request record plus
 * everything needed to publish it and later unseal the approver's grant.
 * `code` is what the requester displays for the human to type into the
 * approving app — this module never renders it, just returns the string.
 * Carries its own `rendezvous`/`layout` so {@link fetchSpaceJoinGrant} /
 * {@link awaitSpaceJoinGrant} can take the session directly.
 */
export interface SpaceJoinRequestSession {
  request: SpaceJoinRequestPayload
  device: GeneratedDeviceKeys
  code: string
  rendezvous: SpaceJoinRendezvous
  layout: SpaceLayout
  /** Publish (or re-publish) the request record to the rendezvous. */
  publish(): Promise<void>
}

/**
 * Requester side, step 1: create and publish a join request.
 *
 * ```ts
 * const rendezvous = { baseUrl: "https://sync.example/sync", namespace: "dk" }
 * const session = await startSpaceJoinRequest({ origin: "https://myapp.example", rendezvous })
 * await session.publish()
 * showCodeToUser(session.code)
 * const grant = await awaitSpaceJoinGrant(session)
 * ```
 *
 * The first `publish()` is **create-only** (`baseHash: null`): it fails with a
 * `ConflictError` rather than silently adopting whatever already occupies the
 * slot. Every later `publish()` uses this session's OWN remembered hash rather
 * than re-pulling and trusting whatever the server currently reports, so a
 * hostile overwrite between two `publish()` calls surfaces as a loud conflict
 * instead of quietly becoming this session's new baseline.
 */
export function startSpaceJoinRequest(opts: StartSpaceJoinRequestOptions): SpaceJoinRequestSession {
  const layout = opts.layout ?? defaultSpaceLayout
  const { request, device, code } = createSpaceJoinRequest(opts)
  const client = anonClient(opts.rendezvous, opts.fetch)
  let lastHash: string | null = null
  // Serializes overlapping publish() calls on the SAME session — without this,
  // two calls in flight at once both read the same lastHash before either
  // awaits, so the one the server processes second gets a real ConflictError
  // caused only by this session's own overlapping write, not third-party
  // tampering, yet it would hit the exact same "treat this code as compromised"
  // signal a genuine hijack produces.
  let queue: Promise<void> = Promise.resolve()
  async function doPublish(): Promise<void> {
    const result = await client.push(
      layout.joinSessionPush(code),
      request as unknown as Record<string, unknown>,
      lastHash,
    )
    lastHash = result.hash
  }
  return {
    request,
    device,
    code,
    rendezvous: opts.rendezvous,
    layout,
    publish() {
      const run = queue.then(() => doPublish())
      // Swallow so a failed publish() doesn't permanently wedge the queue for
      // the NEXT caller's publish() — each call still observes its own
      // rejection via the returned promise.
      queue = run.catch(() => {})
      return run
    },
  }
}

/** Options for {@link fetchSpaceJoinRequestByCode}. */
export interface FetchSpaceJoinRequestOptions {
  code: string
  rendezvous: SpaceJoinRendezvous
  /** Path layout for the rendezvous slot. Default: {@link defaultSpaceLayout}. */
  layout?: SpaceLayout
  fetch?: typeof globalThis.fetch
}

/**
 * Approver side, step 1: look up a request by the code the human typed.
 *
 * Returns `null` only when nothing is published under that code at all (wrong
 * code, or the collection's own TTL already reclaimed it), and also when the
 * slot has already advanced to `phase: "grant"` — there is no pending request
 * to approve in either case. A request that IS still present but past its own
 * `expiresAt` does NOT return `null`; it throws (via
 * {@link parseSpaceJoinRequest}), so the caller can tell "wrong code" apart
 * from "right code, but it expired" and say so accurately.
 *
 * Returns the document's current `hash` alongside the parsed request: that
 * hash is exactly what {@link publishSpaceJoinGrant} needs as its CAS
 * `baseHash`, and taking it from the same read that produced the request is
 * what makes the grant write a genuine pull-then-push update.
 */
export async function fetchSpaceJoinRequestByCode(
  opts: FetchSpaceJoinRequestOptions,
): Promise<{ request: SpaceJoinRequestPayload; hash: string } | null> {
  const layout = opts.layout ?? defaultSpaceLayout
  const client = anonClient(opts.rendezvous, opts.fetch)
  const doc = await pullJoinSession(client, layout.joinSessionPull(opts.code))
  if (!doc) return null
  if (doc.data.phase !== "request") return null
  return { request: parseSpaceJoinRequest(JSON.stringify(doc.data), opts.code), hash: doc.hash }
}

/**
 * Rebuild the `{edPub, kemPub, userId, kemSig}` join-request JSON that
 * `parseJoinRequest` / `inviteToSpace` expect, from a
 * {@link SpaceJoinRequestPayload}'s already-public `devEdPub`/`devKemPub` plus
 * the `joinRequestKemSig` it carries. The sibling of `makeJoinRequest`, for the
 * case where the requesting identity has no `Session` on this side of the
 * exchange (it is a remote ephemeral key, not a wallet this app holds).
 *
 * `userId` is derived with `userIdFromEdPub` if given, else the
 * module-configured global default. Pass the approving session's OWN hook
 * (`session.userIdFromEdPub`) when the app configured a custom one — otherwise
 * this can derive a different `userId` than `parseJoinRequest` recomputes
 * inside `inviteToSpace` (which always uses the session's hook), and every
 * join fails with "userId does not match edPub" even though the request is
 * perfectly valid.
 */
export async function joinRequestFromSpaceJoinRequest(
  request: SpaceJoinRequestPayload,
  userIdFromEdPub?: (edPub: string) => Promise<string>,
): Promise<string> {
  const derive = userIdFromEdPub ?? getSpacesConfig().userIdFromEdPub ?? defaultUserIdFromEdPub
  const req: JoinRequest = {
    edPub: request.devEdPub,
    kemPub: request.devKemPub,
    userId: await derive(request.devEdPub),
    kemSig: request.joinRequestKemSig,
  }
  return JSON.stringify(req)
}

// ── Grant side ─────────────────────────────────────────────────────────────────

/** Options for {@link publishSpaceJoinGrant}. */
export interface PublishSpaceJoinGrantOptions {
  /** The code whose slot is being updated — the seal AAD and the storage key. */
  code: string
  /** The parsed request this grant answers; its `devKemPub` is the seal target. */
  request: SpaceJoinRequestPayload
  /** The approver's Ed25519 keypair — signs the wrap entry so the requester can
   *  authenticate who sealed the grant (`sealedBy`). */
  sealer: SealerKeys
  /** What gets sealed: the space and the member cap minted for the requester,
   *  e.g. `JSON.parse(await inviteToSpace(...))`. */
  grant: { spaceId: string; cap: unknown }
  /** The approver's OWN trusted server config — the same one it used to look the
   *  code up. Never a value read out of the request document. */
  rendezvous: SpaceJoinRendezvous
  /** Path layout for the rendezvous slot. Default: {@link defaultSpaceLayout}. */
  layout?: SpaceLayout
  /** The hash of the document this write replaces — the one
   *  {@link fetchSpaceJoinRequestByCode} returned, or the hash a previous
   *  `publishSpaceJoinGrant` returned when re-publishing. Required: this is a
   *  CAS UPDATE of an existing request document, never a create. */
  baseHash: string
  fetch?: typeof globalThis.fetch
}

/**
 * Approver side, step 2: seal the minted grant to the requester's ephemeral KEM
 * key and CAS-UPDATE the same slot from `phase: "request"` to `phase: "grant"`.
 *
 * The write is guarded by `baseHash`, so a racing writer trying to plant its own
 * grant needs the very hash this approver is using — it loses the race with a
 * `ConflictError` instead of silently overwriting. (And even a bogus write that
 * DID land would only yield ciphertext the requester cannot open, since it is
 * sealed to the wrong KEM key: it denies the exchange, it does not compromise
 * it.) A `ConflictError` here means the slot changed since the request was
 * read — treat the code as compromised, do not retry past it.
 *
 * `code` is the AAD for the seal, so the resulting ciphertext is bound to this
 * slot: copied into a different code's slot it fails to open.
 *
 * Returns the resulting hash so a caller that legitimately re-publishes later
 * can pass it back as `baseHash`.
 */
export async function publishSpaceJoinGrant(opts: PublishSpaceJoinGrantOptions): Promise<{ hash: string }> {
  if (!opts.baseHash) {
    throw new Error(
      "publishSpaceJoinGrant: baseHash is required — this is a CAS update of the request document, "
      + "not a create; pass the hash fetchSpaceJoinRequestByCode returned",
    )
  }
  const layout = opts.layout ?? defaultSpaceLayout
  const client = anonClient(opts.rendezvous, opts.fetch)
  const envelope: GrantEnvelope = {
    v: GRANT_ENVELOPE_VERSION,
    kind: GRANT_ENVELOPE_KIND,
    spaceId: opts.grant.spaceId,
    cap: opts.grant.cap,
  }
  const sealed = await seal(
    new TextEncoder().encode(JSON.stringify(envelope)),
    opts.request.devKemPub,
    opts.sealer,
    opts.code,
  )
  const doc: SpaceJoinGrantPayload = {
    v: 1,
    phase: "grant",
    sealed,
    grantedAt: new Date().toISOString(),
  }
  return client.push(layout.joinSessionPush(opts.code), doc as unknown as Record<string, unknown>, opts.baseHash)
}

/**
 * Approver side: clear the join-session slot at unpair time.
 *
 * Best-effort blind overwrite — the one place "overwrite whatever is there and
 * retry" is correct: cleanup must succeed even without a remembered hash (in
 * -memory state lost across a reload), and "did someone else already overwrite
 * this" is not a meaningful question when the caller's whole intent is
 * "nothing should be published here anymore".
 *
 * This is NOT called automatically after a successful
 * {@link fetchSpaceJoinGrant}: unlike `completeDevicePairing`'s one-shot slot,
 * a live pairing genuinely re-polls its grant over its lifetime. Clearing only
 * stops the CODE from resolving to a usable grant again; it does not revoke a
 * grant already handed out — use `removeSpaceMember` / `revokeSpaceAccess` for
 * that, alongside this, not instead of it.
 *
 * Pulls the RAW result rather than going through the empty-document collapse in
 * {@link pullJoinSession}: an already-cleared slot holds `{}` (exactly what this
 * function writes) but still HAS a hash, and pushing `baseHash: null` against it
 * would conflict on every retry — making a benign double-unpair permanently
 * fail. A 404 (nothing ever published under this code) is likewise not an
 * error here — it means "already nothing to clear", so it is treated as an
 * absent document: `baseHash: null`, i.e. a genuine create-only write (matching
 * the Python twin's `_pull_hash`, which returns `None` for the same case).
 *
 * Uses {@link runCas} rather than a bespoke loop so this gets the same
 * jittered-backoff retry behavior every other CAS write in this package does.
 * One consequence: a `ConflictError` thrown after all retries are exhausted
 * is indistinguishable (same type) from a single transient one — matching
 * every other `runCas` call site in this package, none of which distinguish
 * the two either. A caller that specifically needs to tell "gave up" apart
 * from "one conflict happened" must count its own retries around this call.
 */
export async function clearSpaceJoinGrant(opts: {
  code: string
  rendezvous: SpaceJoinRendezvous
  layout?: SpaceLayout
  fetch?: typeof globalThis.fetch
}): Promise<{ hash: string }> {
  const layout = opts.layout ?? defaultSpaceLayout
  const client = anonClient(opts.rendezvous, opts.fetch)
  const pullPath = layout.joinSessionPull(opts.code)
  const pushPath = layout.joinSessionPush(opts.code)
  return runCas(async () => {
    const current = await client.pull(pullPath).catch((err: unknown) => {
      if (err instanceof StarfishHttpError && err.status === 404) return null
      throw err
    })
    return client.push(pushPath, {}, current ? current.hash ?? "" : null)
  })
}

// ── Requester side: read the grant ─────────────────────────────────────────────

/** The minimum a caller needs to read a grant back — satisfied by a full
 *  {@link SpaceJoinRequestSession}, or reconstructible after a reload from the
 *  code plus the persisted device keys. */
export interface SpaceJoinGrantSession {
  code: string
  device: GeneratedDeviceKeys
  rendezvous: SpaceJoinRendezvous
  layout?: SpaceLayout
}

/** What a successfully unsealed grant carries. */
export interface UnsealedSpaceJoinGrant {
  spaceId: string
  /** The member cap-cert `inviteToSpace` minted for the requester's ephemeral
   *  identity. Opaque here; feed it to `makeSpaceClient` / `acceptSpaceInvite`. */
  cap: unknown
  /** The Ed25519 pubkey that actually sealed this grant, verified via the wrap
   *  entry's signature (never merely claimed — `unseal` always checks it). A
   *  trust-on-first-use pin: record it after the FIRST successful call and pass
   *  it back as `expectedSealer` on every later poll for this code, so a later
   *  writer to the same slot cannot silently replace an established pairing's
   *  grant with their own. Nothing pins WHO this key belongs to on the very
   *  first read — that trust comes from the code being freshly generated here
   *  and delivered to the approver only via the human code/origin exchange. */
  sealedBy: string
}

/** Options for {@link fetchSpaceJoinGrant}. */
export interface FetchSpaceJoinGrantOptions {
  /** TOFU pin: reject a grant not sealed by this Ed25519 pubkey. */
  expectedSealer?: string
  fetch?: typeof globalThis.fetch
}

/**
 * Requester side: read whatever is currently at this code's slot and, if it has
 * advanced to `phase: "grant"`, unseal it.
 *
 * Returns `null` rather than throwing when the slot is still `phase: "request"`
 * (the approver hasn't approved yet) or holds nothing at all — a caller polling
 * in a loop should treat that as "keep waiting", not a hard failure. A slot that
 * IS a grant but fails to unseal (wrong AAD, wrong recipient, unexpected sealer)
 * or carries a malformed envelope throws {@link SpaceJoinGrantIntegrityError}:
 * that is a real integrity signal, not a wait state — {@link awaitSpaceJoinGrant}
 * fails fast on it rather than polling it to the timeout.
 *
 * Does NOT read any space content. Fetching whatever the granted cap unlocks is
 * the caller's job — this primitive delivers the credential and stops.
 */
export async function fetchSpaceJoinGrant(
  session: SpaceJoinGrantSession,
  opts: FetchSpaceJoinGrantOptions = {},
): Promise<UnsealedSpaceJoinGrant | null> {
  const layout = session.layout ?? defaultSpaceLayout
  const client = anonClient(session.rendezvous, opts.fetch)
  const doc = await pullJoinSession(client, layout.joinSessionPull(session.code))
  if (!doc) return null
  if (doc.data.phase !== "grant") return null

  const sealedRaw = doc.data.sealed
  if (
    typeof sealedRaw !== "object" || sealedRaw === null
    || typeof (sealedRaw as Record<string, unknown>).entry !== "object"
    || (sealedRaw as Record<string, unknown>).entry === null
  ) {
    throw new SpaceJoinGrantIntegrityError("space join grant: malformed sealed blob at this code's slot")
  }
  let plaintext: Uint8Array
  try {
    plaintext = await unseal(sealedRaw as unknown as SealedBlob, session.device.kemPriv, {
      aad: session.code,
      ...(opts.expectedSealer !== undefined ? { requireSealer: opts.expectedSealer } : {}),
    })
  } catch (err) {
    // unseal throws plain Error for every failure mode (wrong AAD/relocated,
    // wrong recipient, wrong sealer, tampered ciphertext) — all of them a
    // real integrity signal, never a transient one.
    throw new SpaceJoinGrantIntegrityError(
      `space join grant: failed to unseal — ${err instanceof Error ? err.message : String(err)}`,
      { cause: err },
    )
  }
  let env: Record<string, unknown> | null
  try {
    env = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown> | null
  } catch (err) {
    throw new SpaceJoinGrantIntegrityError("space join grant: malformed grant envelope", { cause: err })
  }
  if (
    typeof env !== "object" || env === null
    || env.v !== GRANT_ENVELOPE_VERSION || env.kind !== GRANT_ENVELOPE_KIND
    || typeof env.spaceId !== "string" || env.cap === undefined || env.cap === null
  ) {
    throw new SpaceJoinGrantIntegrityError("space join grant: malformed grant envelope")
  }
  return {
    spaceId: env.spaceId,
    cap: env.cap,
    sealedBy: (sealedRaw as unknown as SealedBlob).entry.addedBy,
  }
}

const DEFAULT_AWAIT_TIMEOUT_MS = 5 * 60 * 1000
const POLL_MIN_MS = 1000
const POLL_MAX_MS = 5000

/** Capped exponential poll backoff. */
function pollDelay(attempt: number): number {
  return Math.min(POLL_MIN_MS * 2 ** attempt, POLL_MAX_MS)
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new DOMException("aborted", "AbortError"))
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener("abort", () => {
      clearTimeout(timer)
      reject(new DOMException("aborted", "AbortError"))
    })
  })
}

/** Options for {@link awaitSpaceJoinGrant}. */
export interface AwaitSpaceJoinGrantOptions extends FetchSpaceJoinGrantOptions {
  /** Default: 5 minutes. */
  timeoutMs?: number
  signal?: AbortSignal
}

/**
 * Requester side: poll until the approver publishes a grant, or `timeoutMs`
 * elapses.
 *
 * A {@link fetchSpaceJoinGrant} failure (a network blip, a transient server
 * error) does NOT end the wait — it is swallowed and retried on the next tick,
 * same as `fetchSpaceJoinGrant` returning `null` for "not approved yet". Only
 * reaching the deadline ends it: with the last error if there was one (more
 * informative than a bare timeout), else a generic timeout error. An aborted
 * `signal` rejects immediately with an `AbortError`.
 *
 * The ONE exception to "swallow and keep polling": a
 * {@link SpaceJoinGrantIntegrityError} (a slot that IS a grant but doesn't
 * check out — forged/tampered/relocated) rethrows immediately instead of
 * being retried to the timeout. Retrying it would just keep re-reading the
 * same bad document every cycle — this is the fail-fast path
 * `fetchSpaceJoinGrant`'s own docstring promises for "a real integrity
 * signal, not a wait state".
 */
export async function awaitSpaceJoinGrant(
  session: SpaceJoinGrantSession,
  opts: AwaitSpaceJoinGrantOptions = {},
): Promise<UnsealedSpaceJoinGrant> {
  const deadline = Date.now() + (opts.timeoutMs ?? DEFAULT_AWAIT_TIMEOUT_MS)
  let lastErr: unknown
  for (let attempt = 0; ; attempt++) {
    if (opts.signal?.aborted) throw new DOMException("aborted", "AbortError")
    try {
      const result = await fetchSpaceJoinGrant(session, {
        fetch: opts.fetch,
        ...(opts.expectedSealer !== undefined ? { expectedSealer: opts.expectedSealer } : {}),
      })
      if (result) return result
    } catch (err) {
      if (err instanceof SpaceJoinGrantIntegrityError) throw err
      lastErr = err
    }
    if (Date.now() >= deadline) {
      if (lastErr) throw lastErr
      throw new Error("timed out waiting for the space join to be approved")
    }
    await abortableSleep(pollDelay(attempt), opts.signal)
  }
}
