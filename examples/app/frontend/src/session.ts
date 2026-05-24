/**
 * Session builders and owner operations. Pure(ish) async functions that wrap
 * the Starfish identity / keyring / sharing / profile flows and return a
 * `Session` the React layer can render. The chat *sync* itself is handled by the
 * zustand binding (see App.tsx) — this module sets up caps, keyring, encryptor,
 * and the per-user profile.
 */
import type { Encryptor, StarfishClient } from "@drakkar.software/starfish-client"
import {
  assemblePairingBundle,
  bootstrapRootIdentity,
  buildPairingQr,
  installPairingBundle,
  mintDeviceCap,
  parsePairingQr,
} from "@drakkar.software/starfish-identities"
import { addMemberEntry, mintMemberCap } from "@drakkar.software/starfish-sharing"
import {
  addCollectionRecipient,
  createKeyring,
  createKeyringEncryptor,
} from "@drakkar.software/starfish-keyring"
import type { Keyring } from "@drakkar.software/starfish-keyring"
import {
  type DeviceKeys,
  accountScope,
  buildEncryptor,
  generateDeviceKeys,
  keyringName,
  keyringPull,
  keyringPush,
  makeClient,
  membersName,
  membersPull,
  membersPush,
  memberScope,
  ownerScope,
  reSealRoomAtCurrentEpoch,
  roomIdFromCap,
  roomPull,
  roomPush,
  writePseudo,
} from "./starfish.js"

export type Role = "owner" | "member" | "device"

export interface Session {
  role: Role
  name: string
  userId: string
  roomId: string
  keys: DeviceKeys
  chatCap: unknown | null
  chatClient: StarfishClient | null
  accountClient: StarfishClient | null
  encryptor: Encryptor | null
  canWrite: boolean
}

export interface InviteInfo {
  edPub: string
  kemPub: string
  userId: string
}

function deviceSub(keys: DeviceKeys) {
  return { edPubHex: keys.edPub, kemPubHex: keys.kemPub }
}

// ── Owner ────────────────────────────────────────────────────────────────────
export async function buildOwnerSession(passphrase: string, name: string, roomId: string): Promise<Session> {
  const creds = await bootstrapRootIdentity(passphrase)
  const keys = creds.device
  const chatCap = await mintDeviceCap(keys.edPriv, keys.edPub, deviceSub(keys), ownerScope())
  const accountCap = await mintDeviceCap(keys.edPriv, keys.edPub, deviceSub(keys), accountScope(creds.userId))
  const chatClient = makeClient(chatCap, keys.edPriv)
  const accountClient = makeClient(accountCap, keys.edPriv)
  const encryptor = await setupRoom(chatClient, keys, roomId)
  await writePseudo(accountClient, creds.userId, name) // seed the profile pseudo
  return {
    role: "owner",
    name,
    userId: creds.userId,
    roomId,
    keys,
    chatCap,
    chatClient,
    accountClient,
    encryptor,
    canWrite: true,
  }
}

/** Owner-side: create the room's keyring/members/room doc if missing, return a decryptor. */
async function setupRoom(client: StarfishClient, keys: DeviceKeys, roomId: string): Promise<Encryptor> {
  const encryptor = await ownerEnsureKeyring(client, keys, roomId)
  await ensureRoomInitialized(client, encryptor, roomId)
  await ensureMembersInitialized(client, roomId)
  return encryptor
}

/** Owner switches to (or creates) another room. The owner cap already covers all rooms. */
export async function switchRoom(session: Session, roomId: string): Promise<Session> {
  if (!session.chatClient) throw new Error("no chat client")
  const encryptor =
    session.role === "owner"
      ? await setupRoom(session.chatClient, session.keys, roomId)
      : await buildEncryptor(session.chatClient, session.keys, roomId)
  if (!encryptor) throw new Error(`No access to room "${roomId}" (not a keyring recipient).`)
  return { ...session, roomId, encryptor }
}

async function ownerEnsureKeyring(client: StarfishClient, keys: DeviceKeys, roomId: string): Promise<Encryptor> {
  const krRes = await client.pull(keyringPull(roomId)).catch(() => null)
  let keyring = krRes?.data as unknown as Keyring | undefined
  if (!keyring || !keyring.epochs) {
    const created = await createKeyring(
      { edPrivHex: keys.edPriv, edPubHex: keys.edPub },
      [{ subKemHex: keys.kemPub }],
    )
    keyring = created.keyring
    await client.push(keyringPush(roomId), keyring as unknown as Record<string, unknown>, krRes?.hash ?? null)
  }
  // This caller owns (and just created, if absent) the keyring, so pin itself
  // as the trusted adder — createKeyringEncryptor now fails closed without one.
  const enc = await createKeyringEncryptor(
    keyring,
    { kemPubHex: keys.kemPub, kemPrivHex: keys.kemPriv },
    { trustedAdders: [keys.edPub] },
  )
  // KeyringEncryptor.decrypt returns `object`; Encryptor expects `Record<string, unknown>`.
  return enc as unknown as Encryptor
}

async function ensureRoomInitialized(client: StarfishClient, encryptor: Encryptor, roomId: string): Promise<void> {
  const res = await client.pull(roomPull(roomId)).catch(() => null)
  if (res?.data && (res.data as Record<string, unknown>)._encrypted) return
  const sealed = await encryptor.encrypt({ messages: [] })
  await client.push(roomPush(roomId), sealed as Record<string, unknown>, res?.hash ?? null)
}

/** The sharing helpers expect 404 for a missing dir; this server returns 200 `{}`, so pre-seed. */
async function ensureMembersInitialized(client: StarfishClient, roomId: string): Promise<void> {
  const res = await client.pull(membersPull(roomId)).catch(() => null)
  if (res?.data && Array.isArray((res.data as Record<string, unknown>).entries)) return
  await client.push(membersPush(roomId), { v: 1, entries: [] }, res?.hash ?? null)
}

// ── Member ───────────────────────────────────────────────────────────────────
export async function buildMemberSession(passphrase: string, name: string): Promise<Session> {
  const creds = await bootstrapRootIdentity(passphrase)
  const keys = creds.device
  const accountCap = await mintDeviceCap(keys.edPriv, keys.edPub, deviceSub(keys), accountScope(creds.userId))
  const accountClient = makeClient(accountCap, keys.edPriv)
  await writePseudo(accountClient, creds.userId, name)
  return {
    role: "member",
    name,
    userId: creds.userId,
    roomId: "", // assigned from the member cap on activation
    keys,
    chatCap: null,
    chatClient: null,
    accountClient,
    encryptor: null,
    canWrite: false,
  }
}

export async function activateMember(session: Session, capJson: string): Promise<Session> {
  const cap = JSON.parse(capJson) as { sub: string; scope: { ops: string[]; paths?: string[] } }
  if (cap.sub !== session.keys.edPub) {
    throw new Error("This member cap was issued for a different device.")
  }
  const roomId = roomIdFromCap(cap)
  if (!roomId) throw new Error("Member cap is not scoped to a room.")
  const chatClient = makeClient(cap, session.keys.edPriv)
  const encryptor = await buildEncryptor(chatClient, session.keys, roomId)
  if (!encryptor) {
    throw new Error("You're not in the room keyring yet — ask the owner to invite you first.")
  }
  return { ...session, roomId, chatCap: cap, chatClient, encryptor, canWrite: cap.scope.ops.includes("write") }
}

// ── New device ─────────────────────────────────────────────────────────────────
export function startPairing(): { keys: DeviceKeys; qr: string } {
  const keys = generateDeviceKeys()
  const qr = buildPairingQr(keys.edPub, keys.kemPub, ownerScope())
  return { keys, qr }
}

export async function buildDeviceSession(
  name: string,
  keys: DeviceKeys,
  bundleJson: string,
  roomId: string,
): Promise<Session> {
  const bundle = JSON.parse(bundleJson)
  const installed = await installPairingBundle(bundle, keys)
  const cap = installed.credentials.capCert as unknown as { scope: { ops: string[] } }
  const chatClient = makeClient(installed.credentials.capCert, keys.edPriv)
  const encryptor = await buildEncryptor(chatClient, keys, roomId)
  if (!encryptor) {
    throw new Error(`Paired, but not a keyring recipient for "${roomId}" — the first device must authorise this device for that room.`)
  }
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

// ── Owner operations (scoped to the current room) ────────────────────────────
export async function invite(session: Session, info: InviteInfo, canWrite: boolean): Promise<string> {
  if (!session.chatClient) throw new Error("no chat client")
  const cap = await mintMemberCap(
    session.keys.edPriv,
    session.keys.edPub,
    { edPubHex: info.edPub, kemPubHex: info.kemPub, userIdHex: info.userId },
    "chat",
    memberScope(session.roomId, canWrite),
  )
  await addMemberEntry(session.chatClient, membersName(session.roomId), cap, {
    label: info.userId.slice(0, 8),
    addedBy: session.userId,
  })
  await addCollectionRecipient(
    session.chatClient,
    keyringName(session.roomId),
    { subKem: info.kemPub, userId: info.userId, label: info.userId.slice(0, 8) },
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub, kemPriv: session.keys.kemPriv },
    { trustedAdders: [session.keys.edPub] },
  )
  // Re-key history at the current epoch so a member added after a revoke can read it.
  await reSealRoomAtCurrentEpoch(session.chatClient, session.keys, session.roomId)
  return JSON.stringify(cap)
}

export async function authorizeDevice(session: Session, qr: string): Promise<string> {
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
  return JSON.stringify(bundle)
}
