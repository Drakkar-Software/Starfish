/**
 * Single-collection group encryption example.
 *
 * Shows the minimal setup for sharing one encrypted Starfish collection
 * among a small group of users:
 *
 *   1. Admin creates a keyring and includes themselves as a member.
 *   2. Each member builds their own encryptor from the keyring.
 *   3. Members push / pull through SyncManager — the server only ever
 *      sees { _encrypted: "...", _epoch: N }; plaintext never leaves the client.
 *
 * No batching, chunking, or separate keyring collection is required.
 * The keyring is distributed out-of-band (e.g. stored in each member's
 * private vault or shared via a secure channel).
 *
 * Install:
 *   npm install @drakkar.software/starfish-client
 */

import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import {
  deriveGroupKeyPair,
  createGroupKeyring,
  addGroupMember,
  rotateGroupKey,
  createGroupEncryptor,
  type GroupKeyring,
} from "@drakkar.software/starfish-client/group"

const BASE_URL = "https://api.example.com/v1"
const COLLECTION_PATH = "/groups/g1/notes"

// ---------------------------------------------------------------------------
// Step 1 — Admin: create the keyring (run once, store result securely)
//
// The admin includes their own public key so they can also encrypt/decrypt.
// ---------------------------------------------------------------------------

async function adminSetup(): Promise<{ keyring: GroupKeyring; gek: string }> {
  const adminKp = await deriveGroupKeyPair("admin-passphrase", "admin")
  const aliceKp = await deriveGroupKeyPair("alice-passphrase", "alice")
  const bobKp   = await deriveGroupKeyPair("bob-passphrase",   "bob")

  // Admin is included in members so they can encrypt/decrypt too
  const { keyring, gek } = await createGroupKeyring(adminKp, {
    admin: adminKp.publicKey,
    alice: aliceKp.publicKey,
    bob:   bobKp.publicKey,
  })

  // Distribute `keyring` to all members (e.g. push to each member's vault).
  // Store `gek` in the admin's private vault — needed to add future members.
  console.log("keyring created, epoch:", keyring.currentEpoch)
  return { keyring, gek }
}

// ---------------------------------------------------------------------------
// Step 2 — Member: build encryptor from keyring and use SyncManager
// ---------------------------------------------------------------------------

async function memberPush(
  userId: string,
  passphrase: string,
  keyring: GroupKeyring,
  data: Record<string, unknown>,
): Promise<void> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const encryptor = await createGroupEncryptor(keyring, userId, myKp.privateKey)

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer token-${userId}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath:  `/pull${COLLECTION_PATH}`,
    pushPath:  `/push${COLLECTION_PATH}`,
    encryptor,  // replaces encryptionSecret / encryptionSalt
  })

  await sync.push(data)
  console.log(`[${userId}] pushed encrypted data`)
}

async function memberPull(
  userId: string,
  passphrase: string,
  keyring: GroupKeyring,
): Promise<Record<string, unknown>> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const encryptor = await createGroupEncryptor(keyring, userId, myKp.privateKey)

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer token-${userId}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath: `/pull${COLLECTION_PATH}`,
    pushPath: `/push${COLLECTION_PATH}`,
    encryptor,
  })

  await sync.pull()
  const data = sync.getData()
  console.log(`[${userId}] pulled and decrypted:`, data)
  return data
}

// ---------------------------------------------------------------------------
// Step 3 — Admin: add a new member without rotating the key
// ---------------------------------------------------------------------------

async function addMember(
  keyring: GroupKeyring,
  gek: string,
  newMemberId: string,
  newMemberPassphrase: string,
): Promise<GroupKeyring> {
  const adminKp = await deriveGroupKeyPair("admin-passphrase", "admin")
  const newMemberKp = await deriveGroupKeyPair(newMemberPassphrase, newMemberId)

  const updated = await addGroupMember(keyring, adminKp, gek, newMemberId, newMemberKp.publicKey)
  console.log(`added ${newMemberId} to epoch ${updated.currentEpoch}`)
  // Distribute `updated` to all members
  return updated
}

// ---------------------------------------------------------------------------
// Step 4 — Admin: remove a member by rotating to a new epoch
//
// The removed member keeps their old-epoch key but cannot decrypt new documents.
// ---------------------------------------------------------------------------

async function removeMember(
  keyring: GroupKeyring,
  remainingMembers: Record<string, string>,  // userId → publicKey
): Promise<{ keyring: GroupKeyring; gek: string }> {
  const adminKp = await deriveGroupKeyPair("admin-passphrase", "admin")

  const { keyring: rotated, gek: newGek } = await rotateGroupKey(keyring, adminKp, remainingMembers)
  console.log(`rotated to epoch ${rotated.currentEpoch}`)
  // Distribute `rotated` to remaining members; store `newGek` in admin's vault
  return { keyring: rotated, gek: newGek }
}

// ---------------------------------------------------------------------------
// Demonstration (illustrative — requires a real server to run)
// ---------------------------------------------------------------------------

async function main() {
  const { keyring, gek } = await adminSetup()

  // Members push and pull
  await memberPush("alice", "alice-passphrase", keyring, { entries: ["note 1"] })
  await memberPull("bob",   "bob-passphrase",   keyring)

  // Admin can also push/pull (included as a member above)
  await memberPull("admin", "admin-passphrase", keyring)

  // Add a new member
  const updatedKeyring = await addMember(keyring, gek, "charlie", "charlie-passphrase")

  // Remove bob — collect remaining member public keys first
  const adminKp   = await deriveGroupKeyPair("admin-passphrase",   "admin")
  const aliceKp   = await deriveGroupKeyPair("alice-passphrase",   "alice")
  const charlieKp = await deriveGroupKeyPair("charlie-passphrase", "charlie")
  await removeMember(updatedKeyring, {
    admin:   adminKp.publicKey,
    alice:   aliceKp.publicKey,
    charlie: charlieKp.publicKey,
  })
}

main().catch(console.error)
