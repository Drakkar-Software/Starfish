/**
 * Starfish v3.0 — collection-owner pattern.
 *
 * Alice owns the `shared-team` collection. She wants Bob and Carol to be
 * able to write encrypted documents into it.
 *
 * In v3 this is two separate concerns:
 *
 *   1. AUTHORIZATION — Alice mints `kind: "member"` cap-certs for Bob and
 *      Carol scoped to `shared-team` (read+list+write, with the conventional
 *      `!shared-team/_keyring` denylist so only Alice can rotate keys).
 *
 *   2. CONFIDENTIALITY — Alice creates a keyring whose epoch-1 CEK is wrapped
 *      for her own X25519 pub plus Bob's and Carol's. She pushes it to
 *      `shared-team/_keyring`. Bob and Carol unwrap their copy and use the
 *      recovered CEK to read/write encrypted documents.
 *
 * Run:
 *   npx tsx examples/ts/group-owner.ts
 */

import {
  StarfishClient,
  SyncManager,
  type Encryptor,
  type StarfishCapProvider,
} from "@drakkar.software/starfish-client"
import {
  createKeyring,
  addCollectionRecipient,
  listRecipients,
  createKeyringEncryptor,
} from "@drakkar.software/starfish-keyring"
import { bootstrapRootIdentity, type DeviceCredentials } from "@drakkar.software/starfish-identities"
import { mintMemberCap, scopes } from "@drakkar.software/starfish-sharing"

function makeCapProvider(creds: DeviceCredentials): StarfishCapProvider {
  return {
    async getCap() {
      return { cap: creds.capCert, devEdPrivHex: creds.device.edPriv }
    },
  }
}

const BASE_URL = "https://api.example.com/v1"
const COLLECTION = "shared-team"

async function main() {
  // ── 1. Bootstrap the three identities. ───────────────────────────────────
  // In a real deployment, Bob and Carol bootstrap on their own devices and
  // send Alice their KEM pubkey + userId out-of-band (or via the relay/QR
  // pairing helpers — see pairing-qr.ts / pairing-relay.ts).
  const alice = await bootstrapRootIdentity("alice-passphrase")
  const bob = await bootstrapRootIdentity("bob-passphrase")
  const carol = await bootstrapRootIdentity("carol-passphrase")

  const aliceClient = new StarfishClient({
    baseUrl: BASE_URL,
    capProvider: makeCapProvider(alice),
  })

  // ── 2. Alice mints `kind: "member"` cap-certs for Bob and Carol. ─────────
  // These cap-certs let Bob/Carol authenticate to the server with their own
  // device identity but be granted Alice-scoped privileges on
  // `shared-team/*` (with `!shared-team/_keyring` deny rule from `writer`).
  const bobCap = await mintMemberCap(
    alice.device.edPriv,
    alice.device.edPub,
    {
      edPubHex: bob.device.edPub,
      kemPubHex: bob.device.kemPub,
      userIdHex: bob.userId,
    },
    COLLECTION,
    scopes.writer(COLLECTION),
  )
  console.log("[alice] minted member cap for bob, nonce:", bobCap.nonce)

  const carolCap = await mintMemberCap(
    alice.device.edPriv,
    alice.device.edPub,
    {
      edPubHex: carol.device.edPub,
      kemPubHex: carol.device.kemPub,
      userIdHex: carol.userId,
    },
    COLLECTION,
    scopes.writer(COLLECTION),
  )
  console.log("[alice] minted member cap for carol, nonce:", carolCap.nonce)

  // Alice transmits bobCap to Bob and carolCap to Carol (e.g. via a pairing
  // QR or relay). Each saves the cap-cert in their device storage and uses
  // it as their `StarfishCapProvider` when talking to `shared-team/*`.

  // ── 3. Alice creates the keyring with all three recipients in epoch 1. ───
  // She is the adder; she signs each wrapped entry so anyone auditing the
  // keyring can see who granted access to whom.
  const { keyring } = await createKeyring(
    { edPrivHex: alice.device.edPriv, edPubHex: alice.device.edPub },
    [
      { subKemHex: alice.device.kemPub }, // Alice herself
      { subKemHex: bob.device.kemPub },
      { subKemHex: carol.device.kemPub },
    ],
  )

  // Alice pushes the keyring document. The server stores it in plaintext;
  // the wrapped CEKs inside are AES-GCM ciphertext.
  const keyringSync = new SyncManager({
    client: aliceClient,
    pullPath: `/pull/${COLLECTION}/_keyring`,
    pushPath: `/push/${COLLECTION}/_keyring`,
  })
  await keyringSync.push(keyring as unknown as Record<string, unknown>)

  // ── 4. Adding a new member later: addCollectionRecipient. ────────────────
  // Suppose Dan joins after the keyring already exists.
  const dan = await bootstrapRootIdentity("dan-passphrase")
  const danCap = await mintMemberCap(
    alice.device.edPriv,
    alice.device.edPub,
    {
      edPubHex: dan.device.edPub,
      kemPubHex: dan.device.kemPub,
      userIdHex: dan.userId,
    },
    COLLECTION,
    scopes.writer(COLLECTION),
  )
  void danCap

  // `addCollectionRecipient` pulls the keyring, unwraps Alice's CEK using
  // her KEM priv, wraps the same CEK for Dan, and pushes the updated keyring
  // back (with hash-based conflict detection).
  await addCollectionRecipient(
    aliceClient,
    COLLECTION,
    { subKem: dan.device.kemPub, userId: dan.userId, label: "dan" },
    {
      edPriv: alice.device.edPriv,
      edPub: alice.device.edPub,
      kemPriv: alice.device.kemPriv,
    },
  )
  const { epoch, recipients } = await listRecipients(aliceClient, COLLECTION)
  console.log(`[alice] epoch ${epoch}: ${recipients.length} recipients`)

  // ── 5. Bob authenticates with his cap-cert and writes a document. ────────
  const bobClient = new StarfishClient({
    baseUrl: BASE_URL,
    capProvider: {
      async getCap() {
        return { cap: bobCap, devEdPrivHex: bob.device.edPriv }
      },
    },
  })

  // Bob pulls the keyring and builds his own encryptor.
  const bobKeyringSync = new SyncManager({
    client: bobClient,
    pullPath: `/pull/${COLLECTION}/_keyring`,
    pushPath: `/push/${COLLECTION}/_keyring`,
  })
  await bobKeyringSync.pull()
  const bobKeyring = bobKeyringSync.getData() as unknown as typeof keyring

  const bobEncryptor = (await createKeyringEncryptor(
    bobKeyring,
    {
      kemPubHex: bob.device.kemPub,
      kemPrivHex: bob.device.kemPriv,
    },
    { trustedAdders: [alice.device.edPub] },
  )) as unknown as Encryptor

  const bobDocSync = new SyncManager({
    client: bobClient,
    pullPath: `/pull/${COLLECTION}/doc-1`,
    pushPath: `/push/${COLLECTION}/doc-1`,
    encryptor: bobEncryptor,
  })
  await bobDocSync.push({ author: "bob", text: "hello team" })
  console.log("[bob] pushed encrypted doc-1")
}

main().catch((err) => {
  console.error(err)
})
