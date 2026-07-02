/**
 * Starfish v3.0 — server-free QR pairing demo.
 *
 * Two "devices" run in one process for illustration:
 *
 *   ┌─────────── Existing user (root device) ──────────┐
 *   │ bootstrapRootIdentity(passphrase)                │
 *   │   → DeviceCredentials = { device, capCert, … }   │
 *   │                                                  │
 *   │ assemblePairingBundle(root, parsedQr, ceks)      │
 *   │   → PairingBundle = { capCert(sub=newDev),       │
 *   │                       wrappedCEKs }              │
 *   └──────────────────────────────────────────────────┘
 *                          ▲          │
 *                          │          │
 *                  QR ─────┘          ▼  scan / display QR  ─────┐
 *                                                                │
 *   ┌────────────── New device ────────────────────────┐         │
 *   │ generate dev Ed25519 + X25519 locally            │         │
 *   │ buildPairingQr(devEdPub, devKemPub, requested..) ───────────┘
 *   │                                                  │
 *   │ installPairingBundle(bundle, device)             │
 *   │   → verifies cap-cert signature                  │
 *   │   → unwraps each CEK with device's KEM priv      │
 *   └──────────────────────────────────────────────────┘
 *
 * No network is involved — the only side-channel is the QR code that
 * carries the new device's public keys. The root device may be entirely
 * offline.
 *
 * Run:
 *   npx tsx examples/ts/pairing-qr.ts
 */

import {
  bootstrapRootIdentity,
  buildPairingQr,
  parsePairingQr,
  assemblePairingBundle,
  installPairingBundle,
} from "@drakkar.software/starfish-identities"
import { scopes } from "@drakkar.software/starfish-sharing"
import { createKeyring } from "@drakkar.software/starfish-keyring"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

async function main() {
  // ── Root device: existing user. ──────────────────────────────────────────
  const root = await bootstrapRootIdentity("correct-horse-battery-staple")
  console.log("[root] userId:", root.userId)

  // The root has some encrypted collections. For the demo we have one
  // collection "notes" with its current epoch CEK in memory.
  const { cek: notesCek } = await createKeyring(
    { edPrivHex: root.device.edPriv, edPubHex: root.device.edPub },
    [{ subKemHex: root.device.kemPub }],
  )
  const currentEpochByCollection: Record<string, { epoch: number; cek: Uint8Array }> = {
    notes: { epoch: 1, cek: notesCek },
  }

  // ── New device: generate a fresh device-local keypair. ───────────────────
  const newDevEdPriv = ed25519.utils.randomSecretKey()
  const newDevEdPub = ed25519.getPublicKey(newDevEdPriv)
  const newDevKemPriv = x25519.utils.randomSecretKey()
  const newDevKemPub = x25519.getPublicKey(newDevKemPriv)

  // ── Encode the request as a QR string. ───────────────────────────────────
  // The new device asks for read-only access to the "notes" collection.
  const qr = buildPairingQr(
    bytesToHex(newDevEdPub),
    bytesToHex(newDevKemPub),
    scopes.readOnly("notes"),
  )
  console.log("[new-device] QR payload:", qr.slice(0, 60), "...")

  // ── Root device scans the QR (or reads it from camera buffer). ────────────
  const parsed = parsePairingQr(qr)
  console.log("[root] parsed QR for devEdPub:", parsed.devEdPub.slice(0, 16))

  // ── Root device assembles the bundle: a cap-cert + wrapped CEKs. ─────────
  const bundle = await assemblePairingBundle(
    { edPriv: root.device.edPriv, edPub: root.device.edPub },
    parsed,
    currentEpochByCollection,
    { grantedScope: parsed.requestedScope },
  )
  console.log("[root] bundle wraps collections:", Object.keys(bundle.wrappedCEKs))

  // Bundle travels back to the new device (out-of-band: bluetooth, file,
  // second QR, or a brief relay round-trip — see pairing-relay.ts).

  // ── New device installs the bundle. ──────────────────────────────────────
  // Root pinning is MANDATORY: installPairingBundle throws unless it is told
  // which root to trust (otherwise an attacker could hand the device a bundle
  // signed by their OWN root and hijack the identity). This demo already knows
  // the root's Ed25519 pubkey, so we pin it via `expectedRootEdPub`. In a real
  // first-contact flow where the new device has never seen this root, pass
  // `confirmUnpinnedRoot: (rootEdPub) => { /* show this fingerprint to the user
  // and require explicit confirmation before returning true */ return true }`
  // instead.
  const installed = await installPairingBundle(
    bundle,
    {
      edPriv: bytesToHex(newDevEdPriv),
      edPub: bytesToHex(newDevEdPub),
      kemPriv: bytesToHex(newDevKemPriv),
      kemPub: bytesToHex(newDevKemPub),
    },
    { expectedRootEdPub: root.device.edPub },
  )

  console.log("[new-device] installed; userId =", installed.credentials.userId)
  console.log("[new-device] recovered CEKs:", Object.keys(installed.ceks))
  // The new device persists `installed.credentials` (which contains the
  // cap-cert restricted to read-only access to notes) and the recovered CEKs.
  // It can now read encrypted documents in notes/* by passing the cap-cert
  // as a StarfishCapProvider and the CEK to createKeyringEncryptor().
}

main().catch((err) => {
  console.error(err)
})
