/**
 * Starfish TypeScript client examples.
 *
 * Install:
 *   npm install @starfish/client
 */

import { StarfishClient, SyncManager, createEncryptor, ConflictError } from "@starfish/client"

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

syncManagerExample()
