/**
 * Starfish group encryption example (TypeScript).
 *
 * Shows the full lifecycle: group creation, member join, cross-member
 * read/write, adding a member, and revoking a member via key rotation.
 *
 * Install:
 *   npm install @drakkar.software/starfish-client @drakkar.software/starfish-server
 *
 * Server config needed (encryption: "group"):
 *   see examples/ts/server.ts and add the collections below.
 */

import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import {
  deriveGroupKeyPair,
  createGroupKeyring,
  addGroupMember,
  rotateGroupKey,
  createGroupEncryptor,
  type GroupKeyring,
  type GroupKeyPair,
} from "@drakkar.software/starfish-client/group"

const BASE_URL = "https://api.example.com/v1"
const GROUP_ID = "group-abc"

// ---------------------------------------------------------------------------
// Helper: create an authenticated StarfishClient for a given identity
// ---------------------------------------------------------------------------

function makeClient(userId: string): StarfishClient {
  return new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${userId}` }),
  })
}

// ---------------------------------------------------------------------------
// Step 1 — Admin creates the group keyring
//
// The admin derives their X25519 key pair from their passphrase (deterministic,
// no key storage required), then wraps the Group Encryption Key (GEK) for each
// founding member's public key.
// ---------------------------------------------------------------------------

async function adminCreateGroup(): Promise<void> {
  const adminPassphrase = "admin-secret-passphrase"
  const adminUserId = "admin"

  // Each member must publish their public key first.
  // Here we simulate fetching alice's and bob's public keys.
  const aliceKp = await deriveGroupKeyPair("alice-secret-passphrase", "alice")
  const bobKp = await deriveGroupKeyPair("bob-secret-passphrase", "bob")

  const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)

  // Wrap the GEK for every founding member
  const { keyring, gek } = await createGroupKeyring(adminKp, {
    alice: aliceKp.publicKey,
    bob: bobKp.publicKey,
  })

  console.log("Created keyring, epoch:", keyring.currentEpoch)
  console.log("Members:", Object.keys(keyring.epochs["1"]!.wrappedKeys))

  // Push keyring to Starfish (plaintext — the wrapped keys are already ciphertext)
  const adminClient = makeClient(adminUserId)
  const keyringSync = new SyncManager({
    client: adminClient,
    pullPath: `/pull/groups/${GROUP_ID}/keyring`,
    pushPath: `/push/groups/${GROUP_ID}/keyring`,
    // No encryptor — keyring document is stored in plaintext
  })
  await keyringSync.push(keyring)

  // IMPORTANT: keep `gek` to add future members. Store it in the admin's
  // encrypted private vault (encryption: "delegated"), never send to server.
  console.log("GEK (store securely):", gek.slice(0, 8) + "...")
}

// ---------------------------------------------------------------------------
// Step 2 — Member pulls keyring and writes an encrypted message
//
// Each member derives their own key pair from their passphrase, pulls the
// keyring, unwraps their GEK copy, and uses it as the Encryptor for the
// encrypted chat collection.
// ---------------------------------------------------------------------------

async function memberPostMessage(
  userId: string,
  passphrase: string,
  message: string,
): Promise<void> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const client = makeClient(userId)

  // Pull the keyring (plaintext)
  const keyringSync = new SyncManager({
    client,
    pullPath: `/pull/groups/${GROUP_ID}/keyring`,
    pushPath: `/push/groups/${GROUP_ID}/keyring`,
  })
  await keyringSync.pull()
  const keyringData = keyringSync.getData() as unknown as GroupKeyring

  // Create a multi-epoch encryptor from the keyring
  const encryptor = await createGroupEncryptor(keyringData, userId, myKp.privateKey)

  // Use the encryptor with the encrypted chat collection
  const today = new Date().toISOString().slice(0, 10) // "2026-04-13"
  const chatSync = new SyncManager({
    client,
    pullPath: `/pull/groups/${GROUP_ID}/chat/${today}`,
    pushPath: `/push/groups/${GROUP_ID}/chat/${today}`,
    encryptor, // replaces encryptionSecret/encryptionSalt
  })

  // Append message (atomic read-modify-write with conflict retry)
  await chatSync.update((current) => {
    const messages = (current["messages"] as Array<{id: string; author: string; text: string; ts: number}> | undefined) ?? []
    return {
      ...current,
      messages: [
        ...messages,
        { id: crypto.randomUUID(), author: userId, text: message, ts: Date.now() },
      ],
    }
  })

  console.log(`[${userId}] posted: "${message}"`)
}

// ---------------------------------------------------------------------------
// Step 3 — Member reads messages posted by other members
//
// All members share the same GEK for the current epoch, so any member can
// decrypt any other member's messages. The server never sees plaintext.
// ---------------------------------------------------------------------------

async function memberReadMessages(userId: string, passphrase: string): Promise<void> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const client = makeClient(userId)

  // Pull keyring
  const keyringSync = new SyncManager({
    client,
    pullPath: `/pull/groups/${GROUP_ID}/keyring`,
    pushPath: `/push/groups/${GROUP_ID}/keyring`,
  })
  await keyringSync.pull()
  const keyringData = keyringSync.getData() as unknown as GroupKeyring
  const encryptor = await createGroupEncryptor(keyringData, userId, myKp.privateKey)

  // Pull and decrypt today's chat
  const today = new Date().toISOString().slice(0, 10)
  const chatSync = new SyncManager({
    client,
    pullPath: `/pull/groups/${GROUP_ID}/chat/${today}`,
    pushPath: `/push/groups/${GROUP_ID}/chat/${today}`,
    encryptor,
  })
  await chatSync.pull()
  const data = chatSync.getData() as { messages: Array<{author: string; text: string}> }

  console.log(`[${userId}] read ${data.messages?.length ?? 0} messages:`)
  for (const msg of data.messages ?? []) {
    console.log(`  ${msg.author}: ${msg.text}`)
  }
}

// ---------------------------------------------------------------------------
// Step 4 — Admin adds a new member (no GEK rotation)
//
// The new member can read all existing epoch-1 documents and new ones.
// The admin wraps the current GEK for the new member — no re-encryption needed.
// ---------------------------------------------------------------------------

async function adminAddMember(
  adminPassphrase: string,
  adminUserId: string,
  currentGek: string,         // kept by admin from createGroupKeyring
  newMemberId: string,
  newMemberPublicKey: string,
): Promise<void> {
  const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)
  const adminClient = makeClient(adminUserId)

  // Pull current keyring
  const keyringSync = new SyncManager({
    client: adminClient,
    pullPath: `/pull/groups/${GROUP_ID}/keyring`,
    pushPath: `/push/groups/${GROUP_ID}/keyring`,
  })
  await keyringSync.pull()
  const keyringData = keyringSync.getData() as unknown as GroupKeyring

  // Add the new member to the current epoch
  const updatedKeyring = await addGroupMember(
    keyringData,
    adminKp,
    currentGek,
    newMemberId,
    newMemberPublicKey,
  )

  await keyringSync.push(updatedKeyring)
  console.log(`Added ${newMemberId} to epoch ${updatedKeyring.currentEpoch}`)
}

// ---------------------------------------------------------------------------
// Step 5 — Admin removes a member via key rotation
//
// Creates a new epoch with a new GEK. The removed member keeps their old-epoch
// key (they can still read old documents), but they have no key for epoch 2+.
// ---------------------------------------------------------------------------

async function adminRemoveMember(
  adminPassphrase: string,
  adminUserId: string,
  remainingMembers: Record<string, string>, // userId → publicKey
): Promise<string> {
  const adminKp: GroupKeyPair = await deriveGroupKeyPair(adminPassphrase, adminUserId)
  const adminClient = makeClient(adminUserId)

  // Pull current keyring
  const keyringSync = new SyncManager({
    client: adminClient,
    pullPath: `/pull/groups/${GROUP_ID}/keyring`,
    pushPath: `/push/groups/${GROUP_ID}/keyring`,
  })
  await keyringSync.pull()
  const keyringData = keyringSync.getData() as unknown as GroupKeyring

  // Rotate — new epoch, new GEK, wrapped for remaining members only
  const { keyring: rotatedKeyring, gek: newGek } = await rotateGroupKey(
    keyringData,
    adminKp,
    remainingMembers,
  )

  await keyringSync.push(rotatedKeyring)
  console.log(`Rotated to epoch ${rotatedKeyring.currentEpoch}. Removed member has no epoch-${rotatedKeyring.currentEpoch} key.`)

  // Admin keeps the new GEK to add future members to epoch 2+
  return newGek
}

// ---------------------------------------------------------------------------
// Run all examples in sequence
// ---------------------------------------------------------------------------

async function main() {
  console.log("=== Group Encryption Example ===\n")

  console.log("--- Admin creates group ---")
  await adminCreateGroup()

  console.log("\n--- Alice posts a message ---")
  await memberPostMessage("alice", "alice-secret-passphrase", "Hello, group!")

  console.log("\n--- Bob reads messages ---")
  await memberReadMessages("bob", "bob-secret-passphrase")

  console.log("\n--- Admin adds charlie ---")
  const charlieKp = await deriveGroupKeyPair("charlie-secret-passphrase", "charlie")
  // In practice the admin fetches currentGek from their private vault
  const fakeCurrentGek = "a".repeat(64) // placeholder
  await adminAddMember("admin-secret-passphrase", "admin", fakeCurrentGek, "charlie", charlieKp.publicKey)

  console.log("\n--- Admin removes bob (key rotation) ---")
  const aliceKp = await deriveGroupKeyPair("alice-secret-passphrase", "alice")
  const newGek = await adminRemoveMember("admin-secret-passphrase", "admin", {
    alice: aliceKp.publicKey,
    charlie: charlieKp.publicKey,
  })
  console.log("New GEK epoch started. Bob cannot decrypt new messages.")
  console.log("New GEK (store securely):", newGek.slice(0, 8) + "...")
}

main().catch(console.error)
