/**
 * Starfish TypeScript client examples.
 *
 * Install:
 *   npm install starfish-client
 */

import { StarfishClient, SyncManager, createEncryptor, ConflictError, buildInviteUrl, parseInviteUrl, generatePassphrase, deriveCredentials, pullEntitlements } from "@drakkar.software/starfish-client"
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

// ---------------------------------------------------------------------------
// Group encryption — single-collection (admin as member)
//
// Simpler variant: the keyring is built in memory and distributed
// out-of-band (e.g. stored in each member's private vault). No separate
// keyring collection in Starfish is needed. The admin includes themselves
// in the members map so they can also encrypt/decrypt.
// ---------------------------------------------------------------------------

async function groupSingleCollectionSetup(): Promise<{ keyring: GroupKeyring; gek: string }> {
  const adminKp = await deriveGroupKeyPair("admin-passphrase", "admin")
  const aliceKp = await deriveGroupKeyPair("alice-passphrase", "alice")
  const bobKp   = await deriveGroupKeyPair("bob-passphrase",   "bob")

  // Admin includes themselves as a member so they can encrypt/decrypt too
  const { keyring, gek } = await createGroupKeyring(adminKp, {
    admin: adminKp.publicKey,
    alice: aliceKp.publicKey,
    bob:   bobKp.publicKey,
  })

  // Distribute `keyring` to all members (e.g. push to each member's private vault)
  // Store `gek` in the admin's private vault — needed to add future members
  console.log("single-collection keyring created, epoch:", keyring.currentEpoch)
  return { keyring, gek }
}

async function groupSingleCollectionPush(
  userId: string,
  passphrase: string,
  keyring: GroupKeyring,
  data: Record<string, unknown>,
): Promise<void> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const encryptor = await createGroupEncryptor(keyring, userId, myKp.privateKey)

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${userId}` }),
  })

  // One encrypted collection — encryptor replaces encryptionSecret / encryptionSalt
  const sync = new SyncManager({
    client,
    pullPath: "/pull/groups/g1/notes",
    pushPath: "/push/groups/g1/notes",
    encryptor,
  })
  await sync.push(data)
  console.log(`[${userId}] pushed encrypted data`)
}

async function groupSingleCollectionPull(
  userId: string,
  passphrase: string,
  keyring: GroupKeyring,
): Promise<Record<string, unknown>> {
  const myKp = await deriveGroupKeyPair(passphrase, userId)
  const encryptor = await createGroupEncryptor(keyring, userId, myKp.privateKey)

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${userId}` }),
  })

  const sync = new SyncManager({
    client,
    pullPath: "/pull/groups/g1/notes",
    pushPath: "/push/groups/g1/notes",
    encryptor,
  })
  await sync.pull()
  return sync.getData()
}

// ---------------------------------------------------------------------------
// Binary collections: pushBlob / pullBlob
// ---------------------------------------------------------------------------

async function binaryExample() {
  const client = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer my-token-${USER_ID}` }),
  })

  // Push a PNG avatar (accepts ArrayBuffer, Uint8Array, or Blob)
  const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]) // simplified PNG header
  const pushResult = await client.pushBlob(
    `/push/users/${USER_ID}/avatar`,
    pngBytes,
    "image/png",
  )
  console.log("avatar hash:", pushResult.hash)

  // Pull it back as raw bytes
  const blobResult = await client.pullBlob(`/pull/users/${USER_ID}/avatar`)
  console.log("content type:", blobResult.contentType)  // "image/png"
  console.log("etag hash:", blobResult.hash)            // SHA-256 hex or null
  console.log("size (bytes):", blobResult.data.byteLength)

  // Render in a browser:
  // const blob = new Blob([blobResult.data], { type: blobResult.contentType })
  // imgEl.src = URL.createObjectURL(blob)
}

// ---------------------------------------------------------------------------
// Invite links: buildInviteUrl / parseInviteUrl
// ---------------------------------------------------------------------------

async function inviteLinkExample() {
  // Inviting device: generate a passphrase and encode it in a deep link
  const passphrase = generatePassphrase()
  const inviteUrl = buildInviteUrl("myapp://join", {
    p: passphrase,
    name: "Alice",
  })
  console.log("invite URL:", inviteUrl)
  // → "myapp://join?t=eyJwIjoiYWJsZSBhY2lkIC4uLiIsIm5hbWUiOiJBbGljZSJ9"

  // Joining device: decode the URL and bootstrap credentials
  const payload = parseInviteUrl(inviteUrl)
  if (payload) {
    const joinCreds = await deriveCredentials(payload.p as string)
    console.log("joined as userId:", joinCreds.userId)
  }
}

// ---------------------------------------------------------------------------
// Entitlements: reading and granting feature access
// ---------------------------------------------------------------------------

async function entitlementsExample() {
  // ── Client: read your own entitlements ─────────────────────────────────────
  const userClient = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: `Bearer user-token-${USER_ID}` }),
  })

  // Returns the raw feature slug list from the entitlement document.
  // Returns [] if the document doesn't exist yet.
  const features = await pullEntitlements(userClient, USER_ID)
  console.log("my entitlements:", features)
  // e.g. ["premium-package-1", "paid-cloud-sync"]

  if (features.includes("premium-package-1")) {
    // Access a premium-gated collection
    const premiumData = await userClient.pull(`/pull/premium/latest-report`)
    console.log("premium content:", premiumData.data)
  }

  // ── Admin: grant entitlements to a user ────────────────────────────────────
  // Admins push to the user's entitlement document.
  // The server's entitlement enricher picks up the change on the next request
  // (or after the cache TTL expires, default 1 minute).
  const adminClient = new StarfishClient({
    baseUrl: BASE_URL,
    auth: async () => ({ Authorization: "Bearer admin-secret-token" }),
  })

  // Grant premium-package-1 and paid-cloud-sync to a user
  const targetUserId = USER_ID
  const existing = await adminClient.pull(`/pull/users/${targetUserId}/entitlements`)
  const currentFeatures: string[] = (existing.data as any)?.features ?? []

  await adminClient.push(
    `/push/users/${targetUserId}/entitlements`,
    { features: [...new Set([...currentFeatures, "premium-package-1", "paid-cloud-sync"])] },
    existing.hash,  // pass current hash to detect concurrent admin edits
  )
  console.log("entitlements updated for", targetUserId)

  // Revoke a specific entitlement
  const fresh = await adminClient.pull(`/pull/users/${targetUserId}/entitlements`)
  const remaining = ((fresh.data as any)?.features ?? []).filter(
    (f: string) => f !== "paid-cloud-sync",
  )
  await adminClient.push(
    `/push/users/${targetUserId}/entitlements`,
    { features: remaining },
    fresh.hash,
  )
  console.log("paid-cloud-sync revoked")
}

syncManagerExample()
binaryExample()
inviteLinkExample()
entitlementsExample()
