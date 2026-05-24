/**
 * Starfish v3.0 TypeScript client examples.
 *
 * Demonstrates the v3 surface:
 *   • passphrase → root identity (Ed25519 + X25519)
 *   • signed cap-cert minted locally (no server-held keys)
 *   • StarfishClient + cap-cert request signing
 *   • SyncManager + delegated multi-recipient encryption via keyring
 *
 * Install:
 *   npm install @drakkar.software/starfish-client
 *
 * Run:
 *   npx tsx examples/ts/client.ts
 */

import {
  StarfishClient,
  SyncManager,
  ConflictError,
  type StarfishCapProvider,
  type SyncSigner,
  type Encryptor,
} from "@drakkar.software/starfish-client"
import {
  createKeyring,
  createKeyringEncryptor,
  addCollectionRecipient,
  listRecipients,
  type Keyring,
} from "@drakkar.software/starfish-keyring"
import { bootstrapRootIdentity } from "@drakkar.software/starfish-identities"
import { mintMemberCap, scopes } from "@drakkar.software/starfish-sharing"
import { pullEntitlements } from "@drakkar.software/starfish-entitlements"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { ed25519 } from "@noble/curves/ed25519.js"

const BASE_URL = "https://api.example.com/v1"

// ---------------------------------------------------------------------------
// Helper: build a StarfishCapProvider + SyncSigner from a device's keypair
// + cap-cert. Both delegate to the same Ed25519 private key.
// ---------------------------------------------------------------------------

function makeCapProvider(
  capCert: CapCert,
  devEdPrivHex: string,
): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: capCert, devEdPrivHex }
    },
  }
}

function makeSigner(
  devEdPubHex: string,
  devEdPrivHex: string,
): SyncSigner {
  return {
    async getSigner() {
      return {
        devEdPubHex,
        sign: async (payload: Uint8Array) =>
          ed25519.sign(payload, hexToBytes(devEdPrivHex)),
      }
    },
  }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

// ---------------------------------------------------------------------------
// First user, first device: bootstrap a v3 root identity from a passphrase.
// ---------------------------------------------------------------------------
//
// The returned `DeviceCredentials` carry:
//   • rootEdPub  — the user's root Ed25519 public key
//   • userId     — sha256(rootEdPub)[0:16], the storage namespace identifier
//   • device     — Ed25519 + X25519 keys (here, identical to the root pair)
//   • capCert    — self-signed full-scope device cap-cert
//
// Persist `device` + `capCert` securely. The passphrase itself is NOT stored.

async function bootstrapFirstDevice() {
  const creds = await bootstrapRootIdentity("correct-horse-battery-staple")
  console.log("user_id:", creds.userId)
  console.log("rootEdPub:", creds.rootEdPub)

  // Build a cap-cert auth provider for the client.
  const capProvider = makeCapProvider(creds.capCert, creds.device.edPriv)
  const signer = makeSigner(creds.device.edPub, creds.device.edPriv)

  const client = new StarfishClient({
    baseUrl: BASE_URL,
    capProvider,
  })

  // The server expands `{identity}` to creds.userId based on cap-cert binding.
  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${creds.userId}/settings`,
    pushPath: `/push/users/${creds.userId}/settings`,
    signer,
  })

  await sync.pull()
  await sync.push({ theme: "dark", lang: "en" })
  console.log("settings pushed, hash:", sync.getHash())

  return { creds, capProvider, signer }
}

// ---------------------------------------------------------------------------
// Delegated multi-recipient encryption.
//
// In v3 the server holds no encryption keys. A collection's CEK lives inside
// a per-collection keyring document — each recipient gets the CEK wrapped
// for their X25519 public key. The client uses createKeyringEncryptor() to
// encrypt/decrypt with the current epoch's CEK.
// ---------------------------------------------------------------------------

async function delegatedEncryptedCollection() {
  // First, bootstrap our identity so we have a key pair available.
  const creds = await bootstrapRootIdentity("correct-horse-battery-staple")

  // ── Create a brand-new keyring for the "notes" collection. ──
  // The first epoch wraps a fresh random CEK for the bootstrapping device
  // (kem pub). Push the keyring to <collection>/_keyring.
  const { keyring } = await createKeyring(
    { edPrivHex: creds.device.edPriv, edPubHex: creds.device.edPub },
    [{ subKemHex: creds.device.kemPub }],
  )

  const capProvider = makeCapProvider(creds.capCert, creds.device.edPriv)
  const signer = makeSigner(creds.device.edPub, creds.device.edPriv)
  const client = new StarfishClient({ baseUrl: BASE_URL, capProvider })

  // Push the keyring (plaintext document — the wrapped CEKs inside are
  // already ciphertext). `notes/_keyring` is read by everyone who's listed
  // in the wrappedKeys, written by anyone with admin scope on notes/*.
  const keyringSync = new SyncManager({
    client,
    pullPath: "/pull/notes/_keyring",
    pushPath: "/push/notes/_keyring",
    signer,
  })
  await keyringSync.push(keyring as unknown as Record<string, unknown>)

  // Now build the encryptor for our device and use it on the actual data
  // collection. Encrypt/decrypt happens client-side; the server only sees
  // `{ _encrypted: "...", _epoch: 1 }`.
  // The cast to Encryptor is structurally safe — KeyringEncryptor returns
  // a strict shape (`{_encrypted, _epoch}`) while Encryptor declares
  // `Record<string, unknown>`. SyncManager only ever reads these fields.
  const encryptor = (await createKeyringEncryptor(
    keyring,
    {
      kemPubHex: creds.device.kemPub,
      kemPrivHex: creds.device.kemPriv,
    },
    { trustedAdders: [creds.device.edPub] },
  )) as unknown as Encryptor

  const notesSync = new SyncManager({
    client,
    pullPath: `/pull/users/${creds.userId}/notes`,
    pushPath: `/push/users/${creds.userId}/notes`,
    encryptor,
    signer,
  })
  await notesSync.push({ items: ["first encrypted note"] })
  console.log("encrypted notes pushed; epoch:", keyring.currentEpoch)
}

// ---------------------------------------------------------------------------
// Adding a teammate to a shared keyring (`addCollectionRecipient`).
//
// Alice owns a `shared-team` collection. Bob has bootstrapped his own
// identity and shared his KEM pub (X25519) with Alice out-of-band.
// Alice fetches the keyring, unwraps the current CEK using her own KEM
// priv, wraps it for Bob's KEM pub, and pushes the updated keyring.
// ---------------------------------------------------------------------------

async function shareWithTeammate(bobKemPubHex: string, bobUserIdHex: string) {
  const alice = await bootstrapRootIdentity("alice-passphrase")
  const aliceClient = new StarfishClient({
    baseUrl: BASE_URL,
    capProvider: makeCapProvider(alice.capCert, alice.device.edPriv),
  })

  // 1. Mint a `member` cap-cert for Bob with writer scope on shared-team.
  //    (Bob's device pubkeys come from out-of-band onboarding.)
  const bobMemberCap = await mintMemberCap(
    alice.device.edPriv,
    alice.device.edPub,
    {
      edPubHex: bobKemPubHex, // demo placeholder — real ed25519 pub goes here
      kemPubHex: bobKemPubHex,
      userIdHex: bobUserIdHex,
    },
    "shared-team",
    scopes.writer("shared-team"),
  )
  console.log("minted member cap-cert for Bob:", bobMemberCap.nonce)
  // Bob installs this cap-cert into his device storage (out-of-band, e.g. QR).

  // 2. Add Bob to the keyring so he can decrypt shared-team payloads.
  await addCollectionRecipient(
    aliceClient,
    "shared-team",
    { subKem: bobKemPubHex, userId: bobUserIdHex, label: "bob" },
    {
      edPriv: alice.device.edPriv,
      edPub: alice.device.edPub,
      kemPriv: alice.device.kemPriv,
    },
  )

  const { epoch, recipients } = await listRecipients(aliceClient, "shared-team")
  console.log(`shared-team epoch ${epoch}: ${recipients.length} recipient(s)`)
}

// ---------------------------------------------------------------------------
// Conflict resolution + retries (same shape as v2, just typed through v3).
// ---------------------------------------------------------------------------

async function conflictExample(capProvider: StarfishCapProvider, userId: string) {
  const client = new StarfishClient({ baseUrl: BASE_URL, capProvider })
  const sync = new SyncManager({
    client,
    pullPath: `/pull/users/${userId}/notes`,
    pushPath: `/push/users/${userId}/notes`,
    onConflict: (local, remote) => {
      // Remote wins for scalars; union lists.
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
// Binary blobs (avatars, attachments).
// ---------------------------------------------------------------------------

async function binaryExample(capProvider: StarfishCapProvider, userId: string) {
  const client = new StarfishClient({ baseUrl: BASE_URL, capProvider })

  // Push raw PNG bytes.
  const pngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]) // simplified PNG header
  const pushResult = await client.pushBlob(
    `/push/users/${userId}/avatar`,
    pngBytes,
    "image/png",
  )
  console.log("avatar hash:", pushResult.hash)

  // Pull it back.
  const blob = await client.pullBlob(`/pull/users/${userId}/avatar`)
  console.log("content type:", blob.contentType) // "image/png"
  console.log("etag hash:", blob.hash)
  console.log("size (bytes):", blob.data.byteLength)
}

// ---------------------------------------------------------------------------
// Entitlements (server-side role enrichment).
//
// Admins push to /users/{userId}/entitlements; the user reads their own
// entitlement document; gated collections check the synthesized
// `entitlement:<slug>` role at request time.
// ---------------------------------------------------------------------------

async function entitlementsExample(capProvider: StarfishCapProvider, userId: string) {
  const client = new StarfishClient({ baseUrl: BASE_URL, capProvider })

  const features = await pullEntitlements(client, userId)
  console.log("my entitlements:", features)
  if (features.includes("premium-package-1")) {
    const r = await client.pull(`/pull/premium/latest-report`)
    console.log("premium content:", r.data)
  }
}

// ---------------------------------------------------------------------------
// Public-read (no cap-cert needed).
// ---------------------------------------------------------------------------

async function publicReadExample() {
  // Omit capProvider for collections whose readRoles include "public".
  const client = new StarfishClient({ baseUrl: BASE_URL })
  const r = await client.pull("/pull/posts/welcome")
  console.log("public post:", r.data)
}

// ---------------------------------------------------------------------------
// Driver — uncomment whichever demo you'd like to run.
// ---------------------------------------------------------------------------

async function main() {
  const { creds, capProvider } = await bootstrapFirstDevice()
  void delegatedEncryptedCollection
  void shareWithTeammate
  void conflictExample
  void binaryExample
  void entitlementsExample
  void publicReadExample
  void capProvider
  void creds
}

// Top-level `await` is fine for tsx — invoke main() unconditionally.
main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err)
})

// Re-export to satisfy isolatedModules-style consumers.
export { makeCapProvider, makeSigner }
