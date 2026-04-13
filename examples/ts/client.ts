/**
 * Starfish TypeScript client examples.
 *
 * Install:
 *   npm install starfish-client
 */

import { StarfishClient, SyncManager, createEncryptor, ConflictError } from "@drakkar.software/starfish-client"
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
const USER_ID = "user-abc"

// ---------------------------------------------------------------------------
// Low-level: pull / push directly
// ---------------------------------------------------------------------------

async function lowLevelExample() {
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  // Pull current state
  const result = await client.pull(`/pull/users/${USER_ID}/settings`)
  console.log("current data:", result.data)
  console.log("hash:", result.hash)

  // Push an update (baseHash must match current hash)
  const newData = { ...result.data, theme: "dark" }
  const success = await client.push(
    `/push/users/${USER_ID}/settings`,
    newData,
    result.hash,
  )
  console.log("pushed, new hash:", success.hash)
}

// ---------------------------------------------------------------------------
// High-level: SyncManager with automatic conflict resolution
// ---------------------------------------------------------------------------

async function syncManagerExample() {
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${USER_ID}/settings`,
    pushPath: `/push/users/${USER_ID}/settings`,
  })

  await sync.pull()
  console.log("data after pull:", sync.getData())

  await sync.push({ theme: "dark", lang: "en" })
  console.log("push done, hash:", sync.getHash())

  // pull-modify-push in one call
  await sync.update((current) => ({ ...current, theme: "light" }))
}

// ---------------------------------------------------------------------------
// E2E encryption (client-side, server never sees plaintext)
// ---------------------------------------------------------------------------

async function encryptedExample() {
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${USER_ID}/notes`,
    pushPath: `/push/users/${USER_ID}/notes`,
    encryptionSecret: "user-generated-secret",
    encryptionSalt: USER_ID,
  })

  await sync.pull()
  // data is automatically decrypted after pull
  console.log("decrypted data:", sync.getData())

  // data is automatically encrypted before push
  await sync.push({ items: ["note 1", "note 2"] })
}

// ---------------------------------------------------------------------------
// Standalone encryptor
// ---------------------------------------------------------------------------

async function encryptorExample() {
  const encryptor = createEncryptor("my-secret", "user-abc")

  const encrypted = await encryptor.encrypt({ hello: "world" })
  // => { _encrypted: "base64..." }

  const decrypted = await encryptor.decrypt(encrypted)
  // => { hello: "world" }
  console.log(decrypted)
}

// ---------------------------------------------------------------------------
// Custom conflict resolver
// ---------------------------------------------------------------------------

async function conflictExample() {
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${USER_ID}/notes`,
    pushPath: `/push/users/${USER_ID}/notes`,
    onConflict: (local, remote) => {
      // Remote wins for scalars; union lists
      const merged: Record<string, unknown> = { ...remote }
      for (const [key, localVal] of Object.entries(local)) {
        const remoteVal = remote[key]
        if (Array.isArray(localVal) && Array.isArray(remoteVal)) {
          merged[key] = [...new Set([...localVal, ...remoteVal])]
        }
      }
      return merged
    },
    maxRetries: 5,
  })

  try {
    await sync.push({ items: ["new note"] })
  } catch (e) {
    if (e instanceof ConflictError) {
      console.log("conflict could not be resolved after max retries")
    }
  }
}

// ---------------------------------------------------------------------------
// Namespaced collections (multi-tenant servers)
// ---------------------------------------------------------------------------

async function namespacedExample() {
  const TENANT = "acme"

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  // Include the namespace prefix in the path.
  // The storagePath on the server uses the tenant as a prefix too,
  // e.g. storagePath: "acme/users/{identity}/settings"
  const sync = new SyncManager({
    client,
    pullPath: `/${TENANT}/pull/${TENANT}/users/${USER_ID}/settings`,
    pushPath: `/${TENANT}/push/${TENANT}/users/${USER_ID}/settings`,
  })

  await sync.pull()
  await sync.push({ theme: "dark" })
  console.log("namespaced push done, hash:", sync.getHash())
}

// ---------------------------------------------------------------------------
// Group encryption — admin creates a group keyring
//
// Each member derives an X25519 key pair deterministically from their
// passphrase. The admin wraps the Group Encryption Key (GEK) for each
// member and pushes the keyring document to Starfish.
// ---------------------------------------------------------------------------

async function groupAdminSetup(): Promise<{ keyring: GroupKeyring; gek: string }> {
  const adminKp = await deriveGroupKeyPair("admin-passphrase", "admin")
  const aliceKp = await deriveGroupKeyPair("alice-passphrase", "alice")
  const bobKp   = await deriveGroupKeyPair("bob-passphrase",   "bob")

  const { keyring, gek } = await createGroupKeyring(adminKp, {
    alice: aliceKp.publicKey,
    bob:   bobKp.publicKey,
  })

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: "Bearer my-token-admin" }),
  })

  // Push keyring in plaintext — the wrapped keys inside are ciphertext
  const keyringSync = new SyncManager({
    client,
    pullPath: "/pull/groups/g1/keyring",
    pushPath: "/push/groups/g1/keyring",
  })
  await keyringSync.push(keyring)

  // Keep `gek` in the admin's private vault — needed to add future members
  console.log("group keyring created, epoch:", keyring.currentEpoch)
  return { keyring, gek }
}

// ---------------------------------------------------------------------------
// Group encryption — member posts an encrypted message
//
// The member pulls the keyring, unwraps their GEK copy, and uses the
// resulting Encryptor with SyncManager (replaces encryptionSecret/Salt).
// ---------------------------------------------------------------------------

async function groupMemberPost(userId: string, passphrase: string, message: string): Promise<void> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${userId}` }),
  })

  // Pull keyring
  const keyringSync = new SyncManager({ client, pullPath: "/pull/groups/g1/keyring", pushPath: "/push/groups/g1/keyring" })
  await keyringSync.pull()
  const encryptor = await createGroupEncryptor(keyringSync.getData() as unknown as GroupKeyring, userId, myKp.privateKey)

  // Write to encrypted chat collection
  const today = new Date().toISOString().slice(0, 10)
  const chatSync = new SyncManager({
    client,
    pullPath:  `/pull/groups/g1/chat/${today}`,
    pushPath:  `/push/groups/g1/chat/${today}`,
    encryptor,  // replaces encryptionSecret / encryptionSalt
  })
  await chatSync.update((current) => {
    const messages = (current["messages"] as Array<{ author: string; text: string }> | undefined) ?? []
    return { ...current, messages: [...messages, { author: userId, text: message, ts: Date.now() }] }
  })
  console.log(`[${userId}] posted: "${message}"`)
}

// ---------------------------------------------------------------------------
// Group encryption — admin adds a new member (no key rotation)
// ---------------------------------------------------------------------------

async function groupAddMember(currentGek: string, newMemberId: string, newMemberPublicKey: string): Promise<void> {
  const adminKp: GroupKeyPair = await deriveGroupKeyPair("admin-passphrase", "admin")
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: "Bearer my-token-admin" }),
  })

  const keyringSync = new SyncManager({ client, pullPath: "/pull/groups/g1/keyring", pushPath: "/push/groups/g1/keyring" })
  await keyringSync.pull()
  const updated = await addGroupMember(
    keyringSync.getData() as unknown as GroupKeyring,
    adminKp, currentGek, newMemberId, newMemberPublicKey,
  )
  await keyringSync.push(updated)
  console.log(`added ${newMemberId} to epoch ${updated.currentEpoch}`)
}

// ---------------------------------------------------------------------------
// Group encryption — admin removes a member via key rotation
//
// A new epoch is created with a new GEK. The removed member retains their
// old-epoch key (can still read old documents) but has no key for new ones.
// ---------------------------------------------------------------------------

async function groupRemoveMember(remainingMembers: Record<string, string>): Promise<string> {
  const adminKp: GroupKeyPair = await deriveGroupKeyPair("admin-passphrase", "admin")
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: "Bearer my-token-admin" }),
  })

  const keyringSync = new SyncManager({ client, pullPath: "/pull/groups/g1/keyring", pushPath: "/push/groups/g1/keyring" })
  await keyringSync.pull()
  const { keyring: rotated, gek: newGek } = await rotateGroupKey(
    keyringSync.getData() as unknown as GroupKeyring,
    adminKp, remainingMembers,
  )
  await keyringSync.push(rotated)
  console.log(`rotated to epoch ${rotated.currentEpoch} — removed member loses access to new documents`)
  return newGek  // store securely in admin's private vault
}

syncManagerExample()
