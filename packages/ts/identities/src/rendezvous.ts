/**
 * Pairing-rendezvous helpers — the phone → computer return leg of QR-in /
 * auto-return device pairing.
 *
 * The new device (e.g. a computer with no camera) shows a QR; the root device
 * (phone) scans it, assembles a {@link PairingBundle}, and drops it in a small
 * anonymous, TTL'd collection at `_pairing/<rendezvousId>`. The new device — which
 * has no cap-cert yet and so cannot read the owner-only `_devices` directory —
 * fetches the bundle from that public slot and installs it.
 *
 * Why a public slot is safe: the bundle's `wrappedCEKs` are already E2E-wrapped
 * to the new device's KEM pubkey, and `installPairingBundle` verifies the root
 * signature + `sub`/`subKem` + `qrNonce` (+ optional `expectedRootEdPub`). So
 * the channel only needs delivery + DoS-resistance, never confidentiality. See
 * `docs/ts/client/24-pairing.md`.
 *
 * The rendezvous location is derived from the QR's existing `qrNonce` — both
 * devices hold it (the new device generated it, the root parsed it from the QR),
 * so no extra field travels in the QR. `qrNonce` was never a secret (it is the
 * anti-replay session binder, visible in the QR and as the storage path).
 */

import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ConflictError, StarfishHttpError } from "@drakkar.software/starfish-client"
import { getBase64 } from "@drakkar.software/starfish-protocol"
import { bytesToHex } from "@drakkar.software/starfish-keyring"
import type { PairingBundle } from "./pairing.js"

/** Collection storage-path prefix for rendezvous slots. */
export const RENDEZVOUS_PREFIX = "_pairing"

const MAX_RETRIES = 3

/**
 * Path-safe rendezvous storage path derived from the (standard-base64) `qrNonce`.
 *
 * `qrNonce` is standard base64 (may contain `+`/`/`/`=`), so it is decoded to
 * bytes and re-encoded as hex to keep the storage path URL/path-safe. Both
 * devices derive the identical path from the same `qrNonce`.
 */
export function rendezvousPathFor(qrNonce: string): string {
  return `${RENDEZVOUS_PREFIX}/${bytesToHex(getBase64().decode(qrNonce))}`
}

async function pullHash(client: StarfishClient, path: string): Promise<string | null> {
  try {
    const result = await client.pull(`/pull/${path}`)
    return result.hash
  } catch (err) {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  }
}

/**
 * Root (phone) side: write the assembled bundle to the rendezvous slot.
 *
 * Last-write-wins: pulls the slot's current baseHash and pushes with it, so the
 * write succeeds whether the slot is empty (fresh `qrNonce`) or already holds a
 * stale/junk value. Retries on a concurrent-write conflict.
 */
export async function pushPairingBundle(
  client: StarfishClient,
  qrNonce: string,
  bundle: PairingBundle,
): Promise<void> {
  const path = rendezvousPathFor(qrNonce)
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const baseHash = await pullHash(client, path)
    try {
      await client.push(`/push/${path}`, bundle as unknown as Record<string, unknown>, baseHash)
      return
    } catch (err) {
      if (err instanceof ConflictError && attempt < MAX_RETRIES - 1) continue
      throw err
    }
  }
  throw new Error(`pushPairingBundle: too many baseHash conflicts at ${path}`)
}

/**
 * New-device (computer) side: a SINGLE fetch of the rendezvous slot — no
 * polling. Returns the bundle, or `null` when the slot is still empty (the root
 * hasn't pushed yet, or the slot expired) so the UI can prompt the user to
 * finish on the root device and trigger another fetch.
 *
 * The caller installs the returned bundle (`installPairingBundle`) and SHOULD
 * then call {@link clearPairingBundle} to one-shot the slot.
 */
export async function fetchPairingBundle(
  client: StarfishClient,
  qrNonce: string,
): Promise<PairingBundle | null> {
  const path = rendezvousPathFor(qrNonce)
  let data: unknown
  try {
    data = (await client.pull(`/pull/${path}`)).data
  } catch (err) {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  }
  // Empty slot (never written, or TTL-expired → server returns `{}`).
  if (!data || typeof data !== "object" || (data as PairingBundle).capCert === undefined) {
    return null
  }
  return data as PairingBundle
}

/**
 * Best-effort one-shot cleanup: overwrite the rendezvous slot with `{}` after a
 * successful install so the bundle is not left readable. Cryptographically the
 * bundle is useless to anyone but this device, so a failure here is harmless —
 * the collection's TTL is the real backstop. Swallows conflicts/errors.
 */
export async function clearPairingBundle(
  client: StarfishClient,
  qrNonce: string,
): Promise<void> {
  const path = rendezvousPathFor(qrNonce)
  try {
    const baseHash = await pullHash(client, path)
    await client.push(`/push/${path}`, {}, baseHash)
  } catch {
    // best-effort; TTL expires the slot regardless
  }
}
