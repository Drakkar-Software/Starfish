/**
 * Starfish v3.0 — server-relay pairing demo.
 *
 * When QR-code exchange isn't practical (e.g. cross-device, remote teammate),
 * the same pairing flow can be relayed through an untrusted server using a
 * short 6-digit code as the only shared secret.
 *
 * Plaintext request:    {devEdPub, devKemPub}
 * Plaintext response:   <PairingBundle as JSON>
 *
 * Both are encrypted with AES-GCM keyed off PBKDF2(code, salt = "starfish-pair"||requestNonce).
 *
 * Sequence:
 *   1. New device generates a keypair.
 *   2. Existing user reads the code (out-of-band, e.g. spoken aloud).
 *   3. New device builds an encrypted PairingRequest and uploads to relay.
 *   4. Existing user's root device polls the relay, decrypts the request.
 *   5. Root device assembles the bundle and uploads an encrypted PairingResponse.
 *   6. New device polls the relay, decrypts the response, installs.
 *
 * The relay sees only opaque ciphertext + the request-nonce. A passive
 * observer cannot recover credentials without the 6-digit code.
 *
 * Run:
 *   npx tsx examples/ts/pairing-relay.ts
 */

import {
  bootstrapRootIdentity,
  buildPairingRequest,
  readPairingRequest,
  buildPairingResponse,
  readPairingResponse,
  assemblePairingBundle,
  installPairingBundle,
  parsePairingQr,
  buildPairingQr,
} from "@drakkar.software/starfish-identities"
import { createKeyring } from "@drakkar.software/starfish-keyring"
import { scopes } from "@drakkar.software/starfish-sharing"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

async function main() {
  const PAIRING_CODE = "428193" // 6-digit numeric, shown briefly on root device

  // ── Root device: existing user. ──────────────────────────────────────────
  const root = await bootstrapRootIdentity("correct-horse-battery-staple")
  const { cek: notesCek } = await createKeyring(
    { edPrivHex: root.device.edPriv, edPubHex: root.device.edPub },
    [{ subKemHex: root.device.kemPub }],
  )

  // ── New device: generate a fresh local keypair. ──────────────────────────
  const newDevEdPriv = ed25519.utils.randomSecretKey()
  const newDevEdPub = bytesToHex(ed25519.getPublicKey(newDevEdPriv))
  const newDevKemPriv = x25519.utils.randomSecretKey()
  const newDevKemPub = bytesToHex(x25519.getPublicKey(newDevKemPriv))

  // ── Step 1: new device → relay (encrypted PairingRequest). ───────────────
  // The request carries the new device's public keys plus a proof-of-possession
  // signature over them (made with the device's edPriv), so a relay cannot swap
  // the KEM pubkey for one it controls. `edPriv` is required for that signature.
  const encryptedReq = await buildPairingRequest(
    { edPriv: bytesToHex(newDevEdPriv), edPub: newDevEdPub, kemPub: newDevKemPub },
    PAIRING_CODE,
  )
  console.log("[new-device] uploaded request, nonce:", encryptedReq.requestNonce)

  // Relay would now store this blob keyed by some short-lived handle. The
  // root device polls for it via the same handle. We simulate the round trip:
  const relayedRequest = encryptedReq

  // ── Step 2: root reads request, scope is decided by the root user UX. ────
  const decrypted = await readPairingRequest(relayedRequest, PAIRING_CODE)
  console.log("[root] received request for devEdPub:", decrypted.devEdPub.slice(0, 16))

  // The new device declared no scope in its request (intentionally minimal),
  // so the root device decides what to grant. Here: read-only access to
  // "notes". We rebuild a parsed-QR shape from the relayed fields so we can
  // reuse `assemblePairingBundle`.
  const parsed = parsePairingQr(
    buildPairingQr(decrypted.devEdPub, decrypted.devKemPub, scopes.readOnly("notes")),
  )

  const bundle = await assemblePairingBundle(
    { edPriv: root.device.edPriv, edPub: root.device.edPub },
    parsed,
    { notes: { epoch: 1, cek: notesCek } },
    { grantedScope: parsed.requestedScope },
  )

  // ── Step 3: root → relay (encrypted PairingResponse). ────────────────────
  const encryptedResp = await buildPairingResponse(
    bundle,
    PAIRING_CODE,
    relayedRequest.requestNonce,
  )
  console.log("[root] uploaded response")

  // ── Step 4: new device polls relay, decrypts response. ───────────────────
  const recoveredBundle = await readPairingResponse(encryptedResp, PAIRING_CODE)
  console.log("[new-device] received bundle, installing…")

  const installed = await installPairingBundle(recoveredBundle, {
    edPriv: bytesToHex(newDevEdPriv),
    edPub: newDevEdPub,
    kemPriv: bytesToHex(newDevKemPriv),
    kemPub: newDevKemPub,
  })

  console.log("[new-device] paired; userId =", installed.credentials.userId)
  console.log("[new-device] CEKs recovered:", Object.keys(installed.ceks))
  // The new device now has a cap-cert scoped to read notes/* and the CEKs
  // needed to decrypt the documents under that path. The relay never saw
  // the cap-cert in plaintext.
}

main().catch((err) => {
  console.error(err)
})
