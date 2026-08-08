/**
 * Device-code space-join pairing over ONE public rendezvous slot.
 *
 * A requester holding no wallet and no `Session` generates ephemeral device
 * keys, proves possession of them, and publishes a short human-typeable code. A
 * human types that code into an approving app that DOES hold a `Session`; the
 * approver shows `origin`/`label` for a human decision and, only if approved,
 * seals the `{spaceId, cap}` from `inviteToSpace` to the requester's ephemeral
 * KEM key.
 *
 * Both phases live at the SAME path, keyed by `code` alone
 * ({@link SpaceLayout.joinSessionPull}, default `_pairing/session/{code}`), as a
 * union discriminated on `phase`. `"request"` is written create-only
 * (`baseHash: null`); `"grant"` is a CAS update against the request document's
 * hash, so a bogus grant surfaces as a `ConflictError` instead of a silent
 * overwrite. `code` is bound into the crypto twice, as the PoP signing input and
 * as the seal AAD, so neither a signature nor a ciphertext survives relocation to
 * another code's slot.
 *
 * Confidentiality rests on the requester's ephemeral KEM private key, not on the
 * guessability of the code: unlike {@link startDevicePairing}, this flow has one
 * out-of-band channel and cannot PIN-seal. The grant slot is therefore NOT
 * auto-cleared after a successful read, since a live pairing legitimately
 * re-polls it. Call {@link clearSpaceJoinGrant} at unpair time, with the collection's
 * TTL as the outer backstop.
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

/** Crockford-style: no visually-ambiguous 0/O or 1/I/L. 31 symbols over 8
 *  characters ≈ 39.6 bits, uniform thanks to {@link randomCode}'s rejection
 *  sampling, and bounded further by the collection's TTL and rate limit. */
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
const CODE_LENGTH = 8
/** Largest multiple of the alphabet length that fits in a byte (248). Bytes at
 *  or above it are rejected so `byte % 31` stays uniform. A plain modulo would
 *  over-represent A-H by 12.5% in every position. */
const CODE_REJECT_THRESHOLD = Math.floor(256 / CODE_ALPHABET.length) * CODE_ALPHABET.length

const DEFAULT_REQUEST_TTL_SEC = 5 * 60
/** `expiresAt` is NOT covered by popSig, so anyone with the code can rewrite it.
 *  This absolute cap is the real enforcement: `parseSpaceJoinRequest` rejects a
 *  longer window and `createSpaceJoinRequest` clamps to it. */
const MAX_REQUEST_TTL_SEC = 60 * 60

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n)
  globalThis.crypto.getRandomValues(b)
  return b
}

function randomCode(): string {
  const chars: string[] = []
  // Batched draws so a run of rejected bytes doesn't become a syscall per byte.
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

/** Binds `code`/`devEdPub`/`devKemPub` together and proves the requester holds
 *  `devEdPriv`. `code` is the slot address, so a request document relocated to
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
 * Deliberately carries NO rendezvous coordinates and no `code`: the approver
 * must use its OWN trusted server config rather than a host an anonymous writer
 * chose, and the code is already the address, so a copy in the body would
 * only be a second, tamperable one.
 */
export interface SpaceJoinRequestPayload {
  v: 1
  phase: "request"
  devEdPub: string
  devKemPub: string
  /** Ed25519 over {@link popSigningInput}, hex. Possession of `devEdPriv` only,
   *  which is why `origin` remains what the approving human relies on. */
  popSig: string
  /** `signKemSig({kemPub: devKemPub, edPriv: devEdPriv})`, hex. The separate
   *  signature the `{edPub, kemPub, userId, kemSig}` shape `inviteToSpace`
   *  expects; {@link joinRequestFromSpaceJoinRequest} reassembles it. */
  joinRequestKemSig: string
  /** Anyone can write anything here, so the approving side must verify it
   *  (e.g. a `.well-known` fetch) rather than trust it at face value. */
  origin: string
  label?: string
  /** Opaque to this module; validated only as a string array. */
  requestedScopes?: string[]
  createdAt: string
  expiresAt: string
}

/** The `phase: "grant"` half: same document, same slot, after approval. */
export interface SpaceJoinGrantPayload {
  v: 1
  phase: "grant"
  /** `{spaceId, cap}` sealed to the request's `devKemPub`, AAD = `code`. */
  sealed: SealedBlob
  grantedAt: string
}

const GRANT_ENVELOPE_KIND = "starfish-space-join-grant"
const GRANT_ENVELOPE_VERSION = 1

interface GrantEnvelope {
  v: typeof GRANT_ENVELOPE_VERSION
  kind: typeof GRANT_ENVELOPE_KIND
  spaceId: string
  cap: unknown
}

/**
 * The slot HAS advanced to `phase: "grant"` but the grant does not check out:
 * a malformed blob or envelope, or `unseal` rejecting it. Distinct from transport
 * and transient errors so {@link awaitSpaceJoinGrant} can fail fast instead of
 * polling a bad document to the timeout.
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
  /** Clamped to one hour (see `MAX_REQUEST_TTL_SEC`). Default: 5 minutes. */
  ttlSec?: number
}

/**
 * Create a join request: fresh ephemeral device keys (never the caller's own
 * identity), a proof-of-possession signature, and a short human code. Pure:
 * {@link startSpaceJoinRequest} is the publishing wrapper. `code` and `device`
 * come back separately because the caller displays the one and needs the private
 * halves of the other to unseal the eventual grant.
 */
export function createSpaceJoinRequest(opts: CreateSpaceJoinRequestOptions): {
  request: SpaceJoinRequestPayload
  device: GeneratedDeviceKeys
  code: string
} {
  const device = generateDeviceKeys()
  const code = randomCode()
  // Clamped, not just defaulted, so an oversized ttlSec can't build a request
  // parseSpaceJoinRequest would reject. A NEGATIVE ttlSec is left alone (it is
  // how a test builds an already-expired request); only the upper bound applies.
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

// 32-byte keys and 64-byte signatures, hex. Checked BEFORE hexToBytes, which
// allocates proportionally to its input with no ceiling of its own.
const HEX_KEY_LENGTH = 64
const HEX_SIG_LENGTH = 128
const MAX_ORIGIN_LENGTH = 2048
const MAX_LABEL_LENGTH = 200
// C0/C1 controls (a rendered newline lets attacker text pose as extra app
// chrome) plus the bidi override/isolate controls that can visually reorder a
// string, e.g. make a hostile host read as a different one. Always \u escapes,
// never literal control characters in source.
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
 * Parse and validate a request document read from `code`'s slot: verifies the
 * proof-of-possession signature against `code` and rejects an expired or
 * over-long window. `code` is a required argument rather than a body field
 * precisely because passing the slot address in is what makes the document
 * non-relocatable.
 *
 * Bounds `origin`/`label` and rejects control/bidi characters in them, since
 * those are the two fields the approving human reads. Does NOT check that
 * `origin` resolves to anything real (that needs network the approving side
 * performs itself), nor detect IDNA confusables.
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

  // Date.parse returns NaN on garbage and every NaN comparison is false, so a
  // malformed expiresAt would otherwise read as "not expired". Fail closed.
  const expiresAtMs = Date.parse(request.expiresAt)
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) throw new Error("space join request: expired")

  // Anchored to THIS CALL's wall clock, not to the request's own createdAt: an
  // attacker controls both unsigned fields, so a createdAt-relative check passes
  // for createdAt = now+364d / expiresAt = now+364d+1h and keeps the code usable
  // for a year. createdAt is informational only, never a security input.
  if (expiresAtMs - Date.now() > MAX_REQUEST_TTL_SEC * 1000) {
    throw new Error("space join request: expiry window exceeds the maximum this module allows")
  }

  return request
}

// ── Transport helpers ──────────────────────────────────────────────────────────

function anonClient(rendezvous: SpaceJoinRendezvous, fetchFn?: typeof globalThis.fetch): StarfishClient {
  return makeAnonSpaceClient({ baseUrl: rendezvous.baseUrl, namespace: rendezvous.namespace, fetch: fetchFn })
}

/**
 * Returns `null` ONLY for "nothing published there": a 404, or an empty body
 * (an unwritten document pulls as `null`, the string `"null"`, or `{}` depending
 * on the deployment). Every other failure propagates, so a caller polling in a
 * loop can tell "not approved yet" from "the server is unreachable".
 */
async function pullJoinSession(
  client: StarfishClient,
  path: string,
): Promise<{ data: Record<string, unknown>; hash: string } | null> {
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
 * The requester's own end of the exchange: the request record, the `code` to
 * display, and the device keys that unseal the grant. Carries its own
 * `rendezvous`/`layout` so {@link fetchSpaceJoinGrant} / {@link awaitSpaceJoinGrant}
 * can take the session directly.
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
 * The first `publish()` is create-only (`baseHash: null`), so it conflicts
 * rather than adopting whatever already occupies the slot. Later ones present
 * this session's OWN remembered hash instead of re-pulling, so a hostile
 * overwrite in between surfaces as a conflict rather than becoming the baseline.
 */
export function startSpaceJoinRequest(opts: StartSpaceJoinRequestOptions): SpaceJoinRequestSession {
  const layout = opts.layout ?? defaultSpaceLayout
  const { request, device, code } = createSpaceJoinRequest(opts)
  const client = anonClient(opts.rendezvous, opts.fetch)
  let lastHash: string | null = null
  // Serializes overlapping publish() calls on the SAME session: without it both
  // read the same lastHash before either awaits, and the second write 409s on
  // its own sibling, indistinguishable from the hijack signal a real conflict
  // is supposed to mean.
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
      // Swallowed here so a failure doesn't wedge the queue for the next caller;
      // each call still observes its own rejection via the returned promise.
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
 * `null` means there is no pending request to approve: nothing published under
 * that code, or the slot already advanced to `phase: "grant"`. A request that IS
 * present but past its own `expiresAt` throws instead (via
 * {@link parseSpaceJoinRequest}), so the caller can tell "wrong code" from
 * "right code, but expired".
 *
 * The returned `hash` comes from the same read as the request and is exactly
 * what {@link publishSpaceJoinGrant} needs as its CAS `baseHash`.
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
 * `parseJoinRequest` / `inviteToSpace` expect from a
 * {@link SpaceJoinRequestPayload}. The sibling of `makeJoinRequest` for a
 * requesting identity this side holds no `Session` for.
 *
 * Pass the approving session's OWN `userIdFromEdPub` when the app configured a
 * custom one: deriving a different `userId` than `parseJoinRequest` recomputes
 * inside `inviteToSpace` fails every join with "userId does not match edPub".
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
  /** The code whose slot is being updated: the seal AAD and the storage key. */
  code: string
  /** The parsed request this grant answers; its `devKemPub` is the seal target. */
  request: SpaceJoinRequestPayload
  /** The approver's Ed25519 keypair. Signs the wrap entry so the requester can
   *  authenticate who sealed the grant (`sealedBy`). */
  sealer: SealerKeys
  /** What gets sealed: the space and the member cap minted for the requester,
   *  e.g. `JSON.parse(await inviteToSpace(...))`. */
  grant: { spaceId: string; cap: unknown }
  /** The approver's OWN trusted server config, the same one it used to look the
   *  code up. Never a value read out of the request document. */
  rendezvous: SpaceJoinRendezvous
  /** Path layout for the rendezvous slot. Default: {@link defaultSpaceLayout}. */
  layout?: SpaceLayout
  /** Hash of the document this write replaces. Required: this is a CAS update of
   *  an existing request document, never a create. */
  baseHash: string
  fetch?: typeof globalThis.fetch
}

/**
 * Approver side, step 2: seal the minted grant to the requester's ephemeral KEM
 * key and CAS-update the same slot from `phase: "request"` to `phase: "grant"`.
 * `code` is the seal AAD, so the ciphertext is bound to this slot.
 *
 * A `ConflictError` means the slot changed since the request was read: treat
 * the code as compromised and do not retry past it. (A bogus write that DID land
 * would only be ciphertext the requester cannot open: it denies the exchange, it
 * does not compromise it.) Returns the resulting hash for a legitimate later
 * re-publish.
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
 * Approver side: clear the join-session slot at unpair time. Best-effort blind
 * overwrite. Cleanup must work without a remembered hash (in-memory state lost
 * across a reload), and "did someone else overwrite this" is not a meaningful
 * question when the intent is "nothing should be published here anymore".
 *
 * Not called automatically after a successful {@link fetchSpaceJoinGrant}: a live
 * pairing genuinely re-polls its grant. Clearing only stops the CODE from
 * resolving to a usable grant again; revoking an already-issued grant is
 * `removeSpaceMember` / `revokeSpaceAccess`, alongside this rather than instead.
 *
 * Pulls the RAW result rather than going through {@link pullJoinSession}: an
 * already-cleared slot holds `{}` but still HAS a hash, so `baseHash: null`
 * would conflict on every retry and a benign double-unpair could never succeed.
 * A 404 means "nothing to clear" and is treated as absent (`baseHash: null`),
 * matching the Python twin's `_pull_hash`.
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

/** The minimum needed to read a grant back. Satisfied by a full
 *  {@link SpaceJoinRequestSession}, or rebuilt after a reload from the code plus
 *  the persisted device keys. */
export interface SpaceJoinGrantSession {
  code: string
  device: GeneratedDeviceKeys
  rendezvous: SpaceJoinRendezvous
  layout?: SpaceLayout
}

/** What a successfully unsealed grant carries. */
export interface UnsealedSpaceJoinGrant {
  spaceId: string
  /** The member cap-cert minted for the requester's ephemeral identity. Opaque
   *  here; feed it to `makeSpaceClient` / `acceptSpaceInvite`. */
  cap: unknown
  /** The Ed25519 pubkey that actually sealed this grant. `unseal` always
   *  verifies the wrap entry's signature, so this is never merely claimed. A
   *  trust-on-first-use pin: record it after the first successful call and pass
   *  it back as `expectedSealer` on later polls, so a later writer to the same
   *  slot cannot silently replace an established pairing's grant. */
  sealedBy: string
}

/** Options for {@link fetchSpaceJoinGrant}. */
export interface FetchSpaceJoinGrantOptions {
  /** TOFU pin: reject a grant not sealed by this Ed25519 pubkey. */
  expectedSealer?: string
  fetch?: typeof globalThis.fetch
}

/**
 * Requester side: read this code's slot and, if it has advanced to
 * `phase: "grant"`, unseal it.
 *
 * `null` rather than a throw while the slot is still `phase: "request"` or holds
 * nothing at all: a caller polling in a loop should treat that as "keep
 * waiting". A slot that IS a grant but fails to unseal or carries a malformed
 * envelope throws {@link SpaceJoinGrantIntegrityError} instead.
 *
 * Delivers the credential and stops; fetching what the cap unlocks is the
 * caller's job.
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

  const sealed = doc.data.sealed as SealedBlob | null | undefined
  if (typeof sealed !== "object" || sealed === null || typeof sealed.entry !== "object" || sealed.entry === null) {
    throw new SpaceJoinGrantIntegrityError("space join grant: malformed sealed blob at this code's slot")
  }
  let plaintext: Uint8Array
  try {
    plaintext = await unseal(sealed, session.device.kemPriv, {
      aad: session.code,
      ...(opts.expectedSealer !== undefined ? { requireSealer: opts.expectedSealer } : {}),
    })
  } catch (err) {
    // unseal throws a plain Error for every failure mode (wrong AAD/relocated,
    // wrong recipient, wrong sealer, tampered ciphertext), all real integrity
    // signals, never transient ones.
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
  return { spaceId: env.spaceId, cap: env.cap, sealedBy: sealed.entry.addedBy }
}

const DEFAULT_AWAIT_TIMEOUT_MS = 5 * 60 * 1000
const POLL_MIN_MS = 1000
const POLL_MAX_MS = 5000

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
 * elapses. A transport blip or transient server error is swallowed and retried
 * on the next tick, exactly like "not approved yet"; only the deadline ends the
 * wait, throwing the last error if there was one, else a generic timeout. An
 * aborted `signal` rejects immediately.
 *
 * The one exception is {@link SpaceJoinGrantIntegrityError}: a forged, tampered
 * or relocated grant rethrows at once, since re-reading the same bad document
 * every cycle buys nothing.
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
    await abortableSleep(Math.min(POLL_MIN_MS * 2 ** attempt, POLL_MAX_MS), opts.signal)
  }
}
