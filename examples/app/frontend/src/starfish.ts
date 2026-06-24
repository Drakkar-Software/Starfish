/**
 * Thin helpers around the Starfish SDK for the chat demo: key generation, cap
 * scopes, client construction, the keyring decryptor, profiles, and the plain
 * REST calls to the demo-only backend endpoints.
 */
import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import { StarfishClient, buildRevocationList } from "@drakkar.software/starfish-client"
import type { RevocationList } from "@drakkar.software/starfish-client"
import type { Encryptor, StarfishCapProvider } from "@drakkar.software/starfish-client"
import { addCollectionRecipient, createKeyringEncryptor, removeRecipient } from "@drakkar.software/starfish-keyring"
import type { Keyring } from "@drakkar.software/starfish-keyring"
import {
  addDeviceEntry,
  assemblePairingBundle,
  buildPairingQr,
  clearPairingBundle,
  fetchPairingBundle,
  installPairingBundle,
  isSealedEnvelope,
  listDevices,
  openWithPassphrase,
  parsePairingQr,
  provisionDevice as libProvisionDevice,
  pushPairingBundle,
  removeDeviceEntry,
  sealWithPassphrase,
} from "@drakkar.software/starfish-identities"
import type { ScopePreset, DeviceEntry, SealedEnvelope } from "@drakkar.software/starfish-identities"
import { evictMember } from "@drakkar.software/starfish-sharing"
// Type-only — erased under verbatimModuleSyntax, so this introduces no runtime
// import cycle even though session.ts imports values from this module.
import type { Session } from "./session.js"

export type { DeviceEntry } from "@drakkar.software/starfish-identities"

// Origin only — the sync router is mounted at the server root so the path the
// client signs (`/pull/…`) matches the path the server verifies.
export const SYNC_BASE = "http://localhost:8000"
export const API_BASE = "http://localhost:8000"

export const DEFAULT_ROOM = "general"

// Per-room paths. Each room is a document at `chat/rooms/<id>`; its keyring and
// member directory live in sibling namespaces (`chatkeyring/rooms/<id>/_keyring`,
// `chatmembers/rooms/<id>/_members`) so the filesystem store has no file/dir
// collision and read/write member caps can still read the keyring.
export const roomPull = (id: string) => `/pull/chat/rooms/${id}`
export const roomPush = (id: string) => `/push/chat/rooms/${id}`
export const keyringName = (id: string) => `chatkeyring/rooms/${id}` // addCollectionRecipient(client, keyringName(id), …)
export const keyringPull = (id: string) => `/pull/${keyringName(id)}/_keyring`
export const keyringPush = (id: string) => `/push/${keyringName(id)}/_keyring`
export const membersName = (id: string) => `chatmembers/rooms/${id}` // addMemberEntry(client, membersName(id), …)
export const membersPull = (id: string) => `/pull/${membersName(id)}/_members`
export const membersPush = (id: string) => `/push/${membersName(id)}/_members`

// Profiles: a public-readable pseudo document at `user/<id>/profile`.
export const profilePull = (userId: string) => `/pull/user/${userId}/profile`
export const profilePush = (userId: string) => `/push/user/${userId}/profile`

export interface DeviceKeys {
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
}

export function bytesToHex(b: Uint8Array): string {
  let s = ""
  for (const x of b) s += x.toString(16).padStart(2, "0")
  return s
}

/** Standard (non-URL-safe) base64 of bytes — matches the server's base64 decode. */
function bytesToBase64(b: Uint8Array): string {
  let s = ""
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s)
}

/** Generate a fresh device-local keypair (used by a brand-new paired device). */
export function generateDeviceKeys(): DeviceKeys {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPriv: bytesToHex(edPriv),
    edPub: bytesToHex(ed25519.getPublicKey(edPriv)),
    kemPriv: bytesToHex(kemPriv),
    kemPub: bytesToHex(x25519.getPublicKey(kemPriv)),
  }
}

// ── Cap scopes ─────────────────────────────────────────────────────────────
// The resolver matches synthesized `cap:<op>:<collection>` roles by exact string
// (no `*` expansion), so scopes name the `chat` collection explicitly. Paths use
// globs / per-room entries because keyring/members live in sibling namespaces.

/** Full owner/device access: every room + its keyring + member directory. */
export function ownerScope(): ScopePreset {
  return {
    ops: ["read", "list", "write"],
    collections: ["chat"],
    paths: ["chat/rooms/**", "chatkeyring/rooms/**", "chatmembers/rooms/**"],
  }
}

/**
 * Member access to ONE room: the room doc + its keyring (to decrypt). Read-only
 * members omit the `write` op, so they never synthesize `cap:write:chat` → 403.
 */
export function memberScope(roomId: string, canWrite: boolean): ScopePreset {
  const ops: ("read" | "write" | "list")[] = canWrite
    ? ["read", "list", "write"]
    : ["read", "list"]
  return { ops, collections: ["chat"], paths: [`chat/rooms/${roomId}`, `${keyringName(roomId)}/_keyring`] }
}

/**
 * Personal cap for the caller's own user namespace: read entitlements + read/write
 * the profile. `cap:write:profile` is what the `profile` collection requires for
 * writes (alongside `cap:write:*` for a root cap).
 */
export function accountScope(userId: string): ScopePreset {
  return {
    ops: ["read", "list", "write"],
    collections: ["entitlements", "profile", "devices"],
    paths: [`users/${userId}/entitlements`, `user/${userId}/profile`, `users/${userId}/_devices`],
  }
}

/** Extract the room id a member cap is scoped to (from its `chat/rooms/<id>` path). */
export function roomIdFromCap(cap: { scope?: { paths?: string[] } }): string | null {
  for (const p of cap.scope?.paths ?? []) {
    const m = /^chat\/rooms\/([^/]+)$/.exec(p)
    if (m) return m[1]
  }
  return null
}

export function capProviderFor(cap: unknown, devEdPrivHex: string): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: cap as never, devEdPrivHex }
    },
  }
}

export function makeClient(cap: unknown, devEdPrivHex: string): StarfishClient {
  return new StarfishClient({ baseUrl: SYNC_BASE, capProvider: capProviderFor(cap, devEdPrivHex) })
}

/**
 * Build a decryptor from a room's keyring. Members read the plaintext keyring
 * document directly (they were added as recipients by the owner) and unwrap the
 * CEK with their own X25519 key. Returns null if the keyring is missing or the
 * caller is not yet a recipient.
 */
export async function buildEncryptor(
  client: StarfishClient,
  keys: DeviceKeys,
  roomId: string,
): Promise<Encryptor | null> {
  try {
    const res = await client.pull(keyringPull(roomId))
    const keyring = res?.data as unknown as Keyring | undefined
    if (!keyring || !keyring.epochs) return null
    // createKeyringEncryptor now fails closed without a trusted-adder pin. In
    // this app the room owner creates the keyring and adds every recipient, so
    // pin the genesis adder (epoch-1 creator); a server-substituted entry whose
    // `addedBy` differs is then ignored. A production app would instead pin the
    // owner's known root key carried out-of-band (e.g. in the room invite).
    const owner = keyring.epochs["1"]?.wrappedKeys[0]?.addedBy
    if (!owner) return null
    const enc = await createKeyringEncryptor(
      keyring,
      { kemPubHex: keys.kemPub, kemPrivHex: keys.kemPriv },
      { trustedAdders: [owner] },
    )
    // KeyringEncryptor.decrypt returns `object`; Encryptor expects
    // `Record<string, unknown>` — structurally identical at runtime.
    return enc as unknown as Encryptor
  } catch {
    return null
  }
}

/**
 * Re-seal a room's document at the keyring's CURRENT epoch. `addCollectionRecipient`
 * only wraps a newcomer into the current epoch, but the room doc may still be
 * sealed under an OLDER one (e.g. a revoke rotated the epoch with no message sent
 * since). A device/member that's only in the current epoch would then fail to
 * decrypt the history with "No key available for epoch N". The caller (an
 * owner/device that is a recipient of every epoch) re-encrypts the current
 * content at the current epoch so any current-epoch recipient can read it.
 * Call this right after adding a recipient. Best-effort — never throws.
 */
export async function reSealRoomAtCurrentEpoch(
  client: StarfishClient,
  keys: DeviceKeys,
  roomId: string,
): Promise<void> {
  try {
    const ownerEnc = await buildEncryptor(client, keys, roomId)
    const res = await client.pull(roomPull(roomId)).catch(() => null)
    const data = res?.data as Record<string, unknown> | undefined
    if (ownerEnc && data && data._encrypted) {
      const sealed = await ownerEnc.encrypt(await ownerEnc.decrypt(data))
      await client.push(roomPush(roomId), sealed, res?.hash ?? null)
    }
  } catch {
    /* best-effort re-key hygiene — the add still succeeded */
  }
}

/**
 * Turn the keyring's low-level "no wrapped key" throw into an actionable
 * message. This fires when the signed-in identity is not a recipient of the
 * room's existing keyring — e.g. the room was first opened under a *different*
 * passphrase, so `ownerEnsureKeyring` reuses that keyring and the current
 * identity was never wrapped in. It is NOT a passphrase-validation failure:
 * every passphrase deterministically derives a valid identity. Non-keyring
 * errors pass through unchanged.
 */
export function friendlyRoomError(err: unknown, roomId: string): string {
  const msg = String((err as Error)?.message ?? err)
  if (/No wrapped key for recipient [0-9a-f]+ in current epoch \d+/.test(msg)) {
    return `This passphrase's identity isn't a member of room "${roomId}". Open a different room id, sign in with the passphrase that first opened "${roomId}", or ask the room owner to invite you.`
  }
  // Decrypt-time failure: the recipient is in the current epoch but some content
  // was sealed under an earlier one (e.g. it was added right after a revoke
  // rotated the epoch, before the room was re-keyed). The owner re-keys by
  // posting a message (or re-adding this device/member).
  if (/No key available for epoch \d+/.test(msg)) {
    return `Some history in "${roomId}" was sealed under an earlier key, before this device joined. Ask the room owner to post a new message (or re-add this device) so it gets re-keyed for you.`
  }
  return msg
}

// ── Profiles ─────────────────────────────────────────────────────────────────
/** Read any user's pseudo. Profiles are public, so a plain fetch suffices. */
export async function readPseudo(userId: string): Promise<string | null> {
  try {
    const r = await fetch(`${API_BASE}${profilePull(userId)}`)
    if (!r.ok) return null
    const body = await r.json()
    const pseudo = body?.data?.pseudo
    return typeof pseudo === "string" ? pseudo : null
  } catch {
    return null
  }
}

/** Write the caller's own pseudo (requires a cap with write on `profile` or `*`). */
export async function writePseudo(client: StarfishClient, userId: string, pseudo: string): Promise<void> {
  const current = await client.pull(profilePull(userId)).catch(() => null)
  await client.push(profilePush(userId), { v: 1, pseudo }, current?.hash ?? null)
}

// ── Demo-only REST endpoints ─────────────────────────────────────────────────
async function post(path: string, body: unknown): Promise<void> {
  await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  })
}

/** Simulated purchase — grants the `premium` slug to a user. */
export const demoGrant = (userId: string) => post("/demo/grant", { userId })
/** Simulated cancellation — revokes paid slugs. */
export const demoRevoke = (userId: string) => post("/demo/revoke", { userId })

// ── Member directory (read-only view for owner UI) ───────────────────────────
export interface MemberRow {
  userId: string
  label: string
  canWrite: boolean
  addedAt: number
  /** Member cap's subject Ed25519 pubkey (hex) — needed to revoke. */
  sub: string
  /** Member cap's nonce (base64) — identifies the cert for revocation/removal. */
  nonce: string
  /** Member's X25519 pubkey (hex) — needed to drop them from the keyring. */
  subKem: string
  /** Member cap's expiry (unix seconds) — required in the revocation entry. */
  exp: number
}

/**
 * Read a room's member directory for the management UI. Owner/device caps can
 * read `chatmembers/rooms/<id>/_members`; a member cap cannot (its scope omits
 * that path), so this returns `[]` for them. Defaults to `[]` on any error.
 */
export async function readMembers(client: StarfishClient, roomId: string): Promise<MemberRow[]> {
  try {
    const res = await client.pull(membersPull(roomId))
    const entries = (res?.data as { entries?: unknown[] } | undefined)?.entries
    if (!Array.isArray(entries)) return []
    return entries
      .map((raw) => raw as {
        subUserId?: string
        sub?: string
        subKem?: string
        nonce?: string
        exp?: number
        label?: string
        scope?: { ops?: string[] }
        addedAt?: number
      })
      .filter((e) => typeof (e.subUserId ?? e.sub) === "string")
      .map((e) => {
        const userId = (e.subUserId ?? e.sub) as string
        return {
          userId,
          label: typeof e.label === "string" ? e.label : userId.slice(0, 8),
          canWrite: Array.isArray(e.scope?.ops) && e.scope!.ops!.includes("write"),
          addedAt: typeof e.addedAt === "number" ? e.addedAt : 0,
          sub: typeof e.sub === "string" ? e.sub : "",
          nonce: typeof e.nonce === "string" ? e.nonce : "",
          subKem: typeof e.subKem === "string" ? e.subKem : "",
          exp: typeof e.exp === "number" ? e.exp : 0,
        }
      })
      .sort((a, b) => a.addedAt - b.addedAt)
  } catch {
    return []
  }
}

export interface AuditRow {
  action: string
  collection: string
  identity: string
  success: boolean
  statusCode: number
}

export async function fetchAudit(): Promise<AuditRow[]> {
  const r = await fetch(`${API_BASE}/audit`)
  return r.ok ? r.json() : []
}

// ── Revocation + device management (owner-side) ──────────────────────────────
// The server REPLACES an issuer's revocation list on each accepted submission
// (it does not merge) and requires a strictly higher `generation`. So we keep a
// cumulative ledger per identity in localStorage and re-send the full revoked
// set, generation-bumped, on every revoke.

interface RevEntry {
  sub: string
  nonce: string
  exp: number
}
interface RevLedger {
  v: 1
  generation: number
  revoked: RevEntry[]
}

const revLedgerKey = (userId: string) => `starfish-revlist-${userId}`

function loadRevLedger(userId: string): RevLedger {
  try {
    const raw = JSON.parse(localStorage.getItem(revLedgerKey(userId)) ?? "")
    if (raw && typeof raw.generation === "number" && Array.isArray(raw.revoked)) {
      return { v: 1, generation: raw.generation, revoked: raw.revoked }
    }
  } catch {
    /* missing/invalid ledger → start fresh */
  }
  return { v: 1, generation: 0, revoked: [] }
}

async function postRevocation(list: Record<string, unknown>): Promise<void> {
  const r = await fetch(`${API_BASE}/revocations`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(list),
  })
  if (!r.ok) {
    const body = (await r.json().catch(() => ({}))) as { reason?: string }
    throw new Error(`Revocation rejected: ${body.reason ?? r.status}`)
  }
}

/**
 * Append `(sub, nonce, exp)` to the caller's cumulative revocation list and
 * submit it signed by the root identity. After this, the cap-resolver returns
 * 401 for that cap on its next request.
 */
async function revokeCap(keys: DeviceKeys, userId: string, target: RevEntry): Promise<void> {
  const ledger = loadRevLedger(userId)
  const revoked = ledger.revoked.filter((e) => !(e.sub === target.sub && e.nonce === target.nonce))
  revoked.push(target)
  const generation = ledger.generation + 1
  // `buildRevocationList` (lib) derives `issUserId` from the pubkey and signs the
  // canonical input — no more hand-rolled signing here.
  const list = buildRevocationList({
    issEdPubHex: keys.edPub,
    issEdPrivHex: keys.edPriv,
    generation,
    revoked,
  })
  await postRevocation(list as unknown as Record<string, unknown>)
  localStorage.setItem(revLedgerKey(userId), JSON.stringify({ v: 1, generation, revoked }))
}

/**
 * Owner: fully revoke a member — revoke their cap (401 on next request), drop
 * them from the room keyring (rotates the epoch so they can't decrypt NEW
 * messages), and remove their member-directory entry. Returns a fresh encryptor
 * for the rotated epoch (the caller stays a recipient).
 */
export async function revokeMember(
  chatClient: StarfishClient,
  keys: DeviceKeys,
  userId: string,
  roomId: string,
  member: { sub: string; nonce: string; exp: number; subKem: string },
): Promise<Encryptor | null> {
  // One call does all three steps (revoke cap + rotate keyring + de-roster) via the
  // lib's `evictMember`, removing the two-step eviction footgun. The caller still
  // owns the revocation ledger (the store needs a strictly-increasing generation).
  const ledger = loadRevLedger(userId)
  const priorRevoked = ledger.revoked.filter((e) => !(e.sub === member.sub && e.nonce === member.nonce))
  const generation = ledger.generation + 1
  await evictMember(
    chatClient,
    {
      keyringCollection: keyringName(roomId),
      membersCollection: membersName(roomId),
      member,
      adder: { edPriv: keys.edPriv, edPub: keys.edPub, kemPriv: keys.kemPriv },
      trustedAdders: [keys.edPub],
      issEdPubHex: keys.edPub,
      issEdPrivHex: keys.edPriv,
      generation,
      priorRevoked,
      submitRevocation: (list: RevocationList) => postRevocation(list as unknown as Record<string, unknown>),
    },
    { rotate: true, revoke: true },
  )
  const revoked = [...priorRevoked, { sub: member.sub, nonce: member.nonce, exp: member.exp }]
  localStorage.setItem(revLedgerKey(userId), JSON.stringify({ v: 1, generation, revoked }))
  return buildEncryptor(chatClient, keys, roomId)
}

/**
 * The directory helpers treat a 404 as "empty", but this server returns 200 with
 * `{}` for a missing document, so the first `addDeviceEntry`/`listDevices` would
 * trip over an undefined `entries`. Pre-seed `{ v: 1, entries: [] }` (same
 * workaround the room keyring/members use during owner setup).
 */
async function ensureDevicesInitialized(accountClient: StarfishClient, userId: string): Promise<void> {
  const path = `users/${userId}/_devices`
  const res = await accountClient.pull(`/pull/${path}`).catch(() => null)
  if (res?.data && Array.isArray((res.data as Record<string, unknown>).entries)) return
  await accountClient.push(`/push/${path}`, { v: 1, entries: [] }, res?.hash ?? null)
}

/** Owner: list this account's recorded devices (keeps expired ones for visibility). */
export async function listOwnDevices(accountClient: StarfishClient, userId: string): Promise<DeviceEntry[]> {
  try {
    await ensureDevicesInitialized(accountClient, userId)
    return await listDevices(accountClient, userId, { includeExpired: true })
  } catch {
    return []
  }
}

/** Owner: record a device cap-cert in the per-user `_devices` directory (best-effort). */
export async function recordDevice(
  accountClient: StarfishClient,
  userId: string,
  cert: Parameters<typeof addDeviceEntry>[2],
  label: string,
): Promise<void> {
  try {
    await ensureDevicesInitialized(accountClient, userId)
    await addDeviceEntry(accountClient, userId, cert, { label, addedBy: userId })
  } catch {
    /* directory is audit/UI metadata — never block the flow on it */
  }
}

/**
 * Owner: fully revoke a device — revoke its cap (401), drop it from the current
 * room's keyring (rotates the epoch), and remove its directory entry. Returns a
 * fresh encryptor for the rotated epoch.
 */
export async function revokeDevice(
  chatClient: StarfishClient,
  accountClient: StarfishClient,
  keys: DeviceKeys,
  userId: string,
  roomId: string,
  device: DeviceEntry,
): Promise<Encryptor | null> {
  await revokeCap(keys, userId, { sub: device.sub, nonce: device.nonce, exp: device.exp })
  if (device.subKem) {
    // A device is only a recipient of the rooms it was paired into — don't fail
    // the revoke if it isn't in this room's keyring.
    await removeRecipient(chatClient, keyringName(roomId), [device.subKem], {
      edPriv: keys.edPriv,
      edPub: keys.edPub,
      kemPriv: keys.kemPriv,
    }, { trustedAdders: [keys.edPub] }).catch(() => {})
  }
  await removeDeviceEntry(accountClient, userId, device.nonce)
  return buildEncryptor(chatClient, keys, roomId)
}

/**
 * Member: locally forget a room — clears the persisted decrypted room (and any
 * rooms-list entry). This does NOT remove the member server-side: members can't
 * write the keyring or member directory by design, so true removal is owner-side
 * (`revokeMember`). The member's cap still exists until the owner revokes it.
 */
export function leaveRoomLocal(userId: string, roomId: string): void {
  try {
    localStorage.removeItem(`chat-${userId}-${roomId}`)
    const rk = `starfish-rooms-${userId}`
    const raw = JSON.parse(localStorage.getItem(rk) ?? "null")
    // Tolerate legacy format (bare array) and current format ({ v: 1, rooms: [...] })
    const list: string[] = Array.isArray(raw)
      ? raw.filter((x): x is string => typeof x === "string")
      : Array.isArray(raw?.rooms)
        ? (raw.rooms as unknown[]).filter((x): x is string => typeof x === "string")
        : []
    localStorage.setItem(rk, JSON.stringify({ v: 1, rooms: list.filter((x) => x !== roomId) }))
  } catch {
    /* ignore storage errors */
  }
}

// ── One-way device provisioning (single setup code, main → new) ──────────────
// An alternative to the two-way pairing exchange (`startPairing` /
// `authorizeDevice` / `buildDeviceSession` in session.ts). Here the MAIN device
// plays BOTH roles: it generates the new device's keypair, mints its cap, and
// adds it to the room keyring — then ships everything in one blob. The new
// device only ever *receives* a JSON; it never sends a request back.
//
// Trade-off vs. two-way pairing: the new device's PRIVATE keys are generated
// off-device and travel inside the blob, so whoever reads the blob owns a full
// clone of the device (private keys + cap + room key). Two-way pairing never
// exposes the new device's private keys. Use one-way only over a channel you'd
// trust with the room key itself.

interface ProvisioningBlob {
  v: 1
  keys: DeviceKeys
  bundle: unknown
  roomId: string
}

/** Cap presets the provisioning UI offers for a new device. */
export type DeviceCapPreset = "owner" | "room-write" | "room-read"

/** Map a UI preset to the scope a provisioned device's cap should carry. */
export function presetScope(preset: DeviceCapPreset, roomId: string): ScopePreset {
  switch (preset) {
    case "room-write":
      return memberScope(roomId, true)
    case "room-read":
      return memberScope(roomId, false)
    case "owner":
    default:
      return ownerScope()
  }
}

/**
 * Main device: provision a new device in one blob, with a caller-chosen cap
 * scope (`preset`) and expiry (`ttlSec`). The library's `provisionDevice` does
 * the off-device keygen + cap mint + bundle assembly; here we layer the
 * room-specific wiring (keyring recipient + re-seal + directory record) on top.
 *
 * `preset` bounds what the device may do: `owner` clones full access, while
 * `room-write` / `room-read` restrict it to the current room (a `room-read`
 * cap omits the write op, so the server returns 403 on send).
 *
 * When `pin` is a non-empty string, the blob is sealed with it (Argon2id →
 * AES-256-GCM) via the library's `sealWithPassphrase`, so the setup code is
 * useless without the PIN. Send the PIN over a DIFFERENT channel than the code.
 */
export async function provisionRoomDevice(
  session: Session,
  preset: DeviceCapPreset = "owner",
  ttlSec?: number,
  pin?: string,
): Promise<string> {
  if (!session.chatClient) throw new Error("no chat client")
  const { deviceKeys: keys, bundle } = await libProvisionDevice(
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub },
    { scope: presetScope(preset, session.roomId), ttlSec },
  )
  // Add the new device to this room's keyring so it can decrypt. A read-only
  // device still needs the CEK to *read*; its cap only omits the write op.
  await addCollectionRecipient(
    session.chatClient,
    keyringName(session.roomId),
    { subKem: keys.kemPub, userId: session.userId, label: "device" },
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub, kemPriv: session.keys.kemPriv },
    { trustedAdders: [session.keys.edPub] },
  )
  // Re-seal the room doc at the current epoch so the new device — wrapped only
  // into the current epoch above — can decrypt history even if a prior revoke
  // left the doc sealed under an older epoch.
  await reSealRoomAtCurrentEpoch(session.chatClient, session.keys, session.roomId)
  // Record it in the directory (best-effort; needs the account cap).
  if (session.accountClient) {
    await recordDevice(session.accountClient, session.userId, bundle.capCert, "provisioned device")
  }
  const blob: ProvisioningBlob = { v: 1, keys, bundle, roomId: session.roomId }
  const json = JSON.stringify(blob)
  if (pin) {
    return JSON.stringify(await sealWithPassphrase(pin, new TextEncoder().encode(json)))
  }
  return json
}

/**
 * New device: install a provisioning blob produced by `provisionRoomDevice`.
 * Reads the device keypair from the blob (it was generated by the main device)
 * and installs the bundle exactly as the two-way `buildDeviceSession` does.
 *
 * If the code is a PIN-sealed envelope, `pin` is required to open it. The
 * envelope check runs FIRST so a sealed code without a PIN prompts for one
 * rather than failing the plaintext-shape check.
 */
export async function buildProvisionedDeviceSession(
  name: string,
  blobJson: string,
  pin?: string,
): Promise<Session> {
  const parsed = JSON.parse(blobJson) as unknown
  let blob: ProvisioningBlob
  if (isSealedEnvelope(parsed)) {
    if (!pin) throw new Error("This setup code is PIN-protected — enter the PIN to install it.")
    let inner: Uint8Array
    try {
      inner = await openWithPassphrase(pin, parsed as SealedEnvelope)
    } catch {
      throw new Error("Incorrect PIN or corrupted setup code.")
    }
    blob = JSON.parse(new TextDecoder().decode(inner)) as ProvisioningBlob
  } else {
    blob = parsed as ProvisioningBlob
  }
  if (blob.v !== 1) {
    throw new Error(`Unsupported setup code version (${blob.v}). Update this device.`)
  }
  if (!blob.keys || !blob.bundle || !blob.roomId) {
    throw new Error("This doesn't look like a setup code from your first device.")
  }
  const keys = blob.keys
  const installed = await installPairingBundle(blob.bundle as Parameters<typeof installPairingBundle>[0], keys)
  const cap = installed.credentials.capCert as unknown as { scope: { ops: string[] } }
  const chatClient = makeClient(installed.credentials.capCert, keys.edPriv)
  const encryptor = await buildEncryptor(chatClient, keys, blob.roomId)
  if (!encryptor) {
    throw new Error(`Provisioned, but not a keyring recipient for "${blob.roomId}".`)
  }
  return {
    role: "device",
    name: name || "device",
    userId: installed.credentials.userId,
    roomId: blob.roomId,
    keys,
    chatCap: installed.credentials.capCert,
    chatClient,
    accountClient: null,
    encryptor,
    canWrite: cap.scope.ops.includes("write"),
  }
}

// ── QR-in / auto-return pairing (rendezvous) ─────────────────────────────────
// A camera-free variant of two-way pairing for a device that cannot scan (e.g. a
// laptop). The NEW device shows its pairing "QR" (a copy-paste blob here); the
// ROOT device pastes it, assembles the bundle, adds the device to the room
// keyring, and PUSHES the bundle to an anonymous, TTL'd rendezvous slot keyed by
// the QR's qrNonce. The new device then does a SINGLE fetch (on an "Added from
// root" click — no polling) to retrieve + install it. No manual bundle-back step.
//
// Both sides talk to the rendezvous with an ANONYMOUS client: the new device has
// no cap yet, and an authed cap does not synthesize the `public` role the slot
// requires. Safety comes from the bundle being self-authenticating (root
// signature + sub/qrNonce checks in installPairingBundle), not from the channel.

/** Anonymous client (no cap) for the public rendezvous collection. */
export function makeAnonClient(): StarfishClient {
  return new StarfishClient({ baseUrl: SYNC_BASE })
}

/**
 * New device: start camera-free pairing. Generates device-local keys and the
 * pairing QR (carrying a fresh qrNonce). Returns the qrNonce too so this device
 * can later derive the rendezvous slot to fetch its bundle from.
 */
export function startQrInPairing(): { keys: DeviceKeys; qr: string; qrNonce: string } {
  const keys = generateDeviceKeys()
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16))
  const qr = buildPairingQr(keys.edPub, keys.kemPub, ownerScope(), nonceBytes)
  return { keys, qr, qrNonce: bytesToBase64(nonceBytes) }
}

/**
 * Root device: "scan" (paste) the new device's QR, assemble its bundle, add it
 * to the current room's keyring, and PUSH the bundle to the rendezvous slot. The
 * new device fetches it itself — nothing to copy back. Returns the qrNonce the
 * bundle was published under (for display).
 */
export async function authorizeDeviceViaRendezvous(session: Session, qr: string): Promise<string> {
  if (!session.chatClient) throw new Error("no chat client")
  const parsed = parsePairingQr(qr)
  // Empty CEK map — the bundle delivers the device cap; decryption comes from
  // adding the device to the current room's keyring below.
  const bundle = await assemblePairingBundle(
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub },
    parsed,
    {},
    // The owner pairs their own device; grant the scope the device requested.
    { grantedScope: parsed.requestedScope },
  )
  await addCollectionRecipient(
    session.chatClient,
    keyringName(session.roomId),
    { subKem: parsed.devKemPub, userId: session.userId, label: "device" },
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub, kemPriv: session.keys.kemPriv },
    { trustedAdders: [session.keys.edPub] },
  )
  // Re-key history at the current epoch so the paired device can read it.
  await reSealRoomAtCurrentEpoch(session.chatClient, session.keys, session.roomId)
  // Record it in the directory (best-effort; needs the account cap).
  if (session.accountClient) {
    await recordDevice(session.accountClient, session.userId, bundle.capCert, "paired device")
  }
  await pushPairingBundle(makeAnonClient(), parsed.qrNonce, bundle)
  return parsed.qrNonce
}

/**
 * New device: a SINGLE fetch of the rendezvous slot (on the "Added from root"
 * click — no polling). Returns null when the root hasn't pushed yet, so the UI
 * can prompt the user to finish on the root device and click again. On a hit it
 * installs the bundle (pinning the qrNonce, and the expected root pub when the
 * user supplied it), one-shots the slot, and returns a device Session.
 */
export async function fetchAndBuildDeviceSession(
  name: string,
  keys: DeviceKeys,
  qrNonce: string,
  roomId: string,
  // REQUIRED: the rendezvous slot (`_pairing/{qrNonce}`) is a public, anonymously
  // writable+overwritable doc, so an attacker can plant a bundle issued by their
  // OWN root. Without pinning the legitimate root the new device would bind to the
  // attacker's identity (account takeover). The caller MUST learn the root pubkey
  // out-of-band (e.g. the user confirms a fingerprint shown on the phone) and pass
  // it here. (UX for that confirmation is a follow-up — see TESTING.md.)
  expectedRootEdPub: string,
): Promise<Session | null> {
  if (!expectedRootEdPub) {
    throw new Error(
      "rendezvous: expectedRootEdPub is required — learn the root pubkey out-of-band " +
        "(e.g. confirm the fingerprint shown on the phone) before installing a bundle from " +
        "the public rendezvous slot, or an attacker could bind this device to their identity.",
    )
  }
  const anon = makeAnonClient()
  const bundle = await fetchPairingBundle(anon, qrNonce)
  if (!bundle) return null
  const installed = await installPairingBundle(
    bundle as Parameters<typeof installPairingBundle>[0],
    keys,
    { expectedQrNonce: qrNonce, expectedRootEdPub },
  )
  const cap = installed.credentials.capCert as unknown as { scope: { ops: string[] } }
  const chatClient = makeClient(installed.credentials.capCert, keys.edPriv)
  const encryptor = await buildEncryptor(chatClient, keys, roomId)
  if (!encryptor) {
    throw new Error(`Paired, but not a keyring recipient for "${roomId}" — the first device must authorise this device for that room.`)
  }
  await clearPairingBundle(anon, qrNonce) // best-effort one-shot
  return {
    role: "device",
    name: name || "device",
    userId: installed.credentials.userId,
    roomId,
    keys,
    chatCap: installed.credentials.capCert,
    chatClient,
    accountClient: null,
    encryptor,
    canWrite: cap.scope.ops.includes("write"),
  }
}
