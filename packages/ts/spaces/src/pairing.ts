/**
 * Device pairing (one-way, PIN-sealed) over a public rendezvous slot.
 *
 * The existing device provisions a new device's keypair + cap bundle
 * ({@link provisionDevice}), seals it with the PIN (Argon2id → AES-GCM), and
 * drops it on the public `_pairing/<nonce>` rendezvous (path from
 * {@link SpaceLayout.pairingPush}). The QR carries only the nonce and the root
 * Ed25519 pubkey; the new device fetches the sealed blob, opens it with the PIN,
 * and installs the cap bundle ({@link installPairingBundle}).
 *
 * Security invariants centralized here:
 *  - the rendezvous push is **hash-guarded** (pull baseHash first) so only the
 *    first write to a slot succeeds;
 *  - the slot is best-effort **cleared** after a successful open;
 *  - root trust is **mandatory** — the expected root pubkey is taken from the QR
 *    payload (or an explicit override), satisfying `installPairingBundle`'s
 *    pinning requirement.
 */
import {
  installPairingBundle,
  openWithPassphrase,
  provisionDevice,
  sealWithPassphrase,
} from "@drakkar.software/starfish-identities"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { bytesToHex } from "@drakkar.software/starfish-keyring"

import { makeAnonSpaceClient } from "./client.js"
import type { DeviceKeys } from "./client.js"
import type { SpaceLayout } from "./config.js"
import { defaultSpaceLayout } from "./layout.js"
import type { Session } from "./session.js"
import { fingerprintFromUserId } from "./session.js"

/** Default QR-payload prefix. Any `*-pair:` prefix is accepted on completion. */
export const DEFAULT_PAIR_PREFIX = "starfish-pair:"

/** Default linked-device cap-cert lifetime — one year keeps it usable long-term. */
const DEFAULT_LINKED_DEVICE_TTL_SEC = 365 * 24 * 60 * 60

function randomNonce(): string {
  const b = new Uint8Array(16)
  globalThis.crypto.getRandomValues(b)
  return bytesToHex(b)
}

export interface StartDevicePairingOptions {
  /** QR-payload prefix to embed. Default: {@link DEFAULT_PAIR_PREFIX}. */
  prefix?: string
  /** Linked-device cap-cert TTL in seconds. Default: one year. */
  ttlSec?: number
  /** Optional fetch override (e.g. a timeout wrapper) for the anon client. */
  fetch?: typeof globalThis.fetch
  /**
   * Called once provisioning is complete, BEFORE the sealed blob is published.
   * Use it to grant the new device access to space keyrings so it can decrypt
   * E2EE content immediately. A thrown error propagates and aborts the push.
   */
  onProvisioned?: (device: { kemPub: string; edPub: string; userId: string }) => void | Promise<void>
}

/**
 * Existing device: provision + PIN-seal a new device, publish to the rendezvous,
 * and return the QR payload (`<prefix><nonce>.<rootEdPub>`).
 *
 * The session's device key acts as the pairing issuer/root, so this is intended
 * for a root/owner session (`buildSession` / `deriveSession`), where
 * `session.keys.edPub === session.ownerEdPub`. Calling it on a linked-device
 * session provisions the new device under the linked device's key, not the account
 * root.
 */
export async function startDevicePairing(
  session: Session,
  pin: string,
  opts?: StartDevicePairingOptions,
): Promise<string> {
  const layout = session.layout
  const { deviceKeys, bundle } = await provisionDevice(
    { edPriv: session.keys.edPriv, edPub: session.keys.edPub },
    { scope: layout.linkedDeviceScope(session.userId), ttlSec: opts?.ttlSec ?? DEFAULT_LINKED_DEVICE_TTL_SEC },
  )
  if (opts?.onProvisioned) {
    await opts.onProvisioned({ kemPub: deviceKeys.kemPub, edPub: deviceKeys.edPub, userId: session.userId })
  }
  const blob = JSON.stringify({ v: 1, keys: deviceKeys, bundle })
  const sealed = await sealWithPassphrase(pin, new TextEncoder().encode(blob))
  const nonce = randomNonce()
  const client = makeAnonSpaceClient({ baseUrl: session.baseUrl, namespace: session.namespace, fetch: opts?.fetch })
  // Hash-guarded push: pull current hash first (null = slot empty / create-only),
  // so only the FIRST write to this slot succeeds.
  const existingHash = await client
    .pull(layout.pairingPull(nonce))
    .then((r) => r.hash)
    .catch((): null => null)
  await client.push(layout.pairingPush(nonce), sealed as unknown as Record<string, unknown>, existingHash)
  return `${opts?.prefix ?? DEFAULT_PAIR_PREFIX}${nonce}.${session.keys.edPub}`
}

export interface PairResult {
  userId: string
  fingerprint: string
  deviceKeys: DeviceKeys
  capCert: CapCert
}

export interface CompleteDevicePairingOptions {
  /** Sync server base URL for the anon client. */
  baseUrl: string
  /** Sync namespace for the anon client. */
  namespace: string
  /** Path layout for the rendezvous slot. Default: {@link defaultSpaceLayout}. */
  layout?: SpaceLayout
  /** Optional fetch override (e.g. a timeout wrapper) for the anon client. */
  fetch?: typeof globalThis.fetch
  /** Expected root Ed25519 pubkey. Defaults to the value in the QR payload. */
  expectedRootEdPub?: string
  /** First-contact confirmation when the QR carries no root (rare). */
  confirmUnpinnedRoot?: (rootEdPub: string) => boolean | Promise<boolean>
}

/**
 * New device: fetch the sealed blob by nonce, open it with the PIN, and install
 * the cap bundle. Accepts any `<prefix>-pair:<nonce>.<rootEdPub>` payload.
 */
export async function completeDevicePairing(
  payload: string,
  pin: string,
  opts: CompleteDevicePairingOptions,
): Promise<PairResult> {
  const layout = opts.layout ?? defaultSpaceLayout
  // Strip the QR prefix generically: the body is `<nonce>.<rootEdPub>` (both hex,
  // no `:`), so everything up to and including the last `:` is the prefix. This
  // accepts the default `starfish-pair:`, any custom `<name>:` / `*-pair:` prefix,
  // and a bare prefix-less `<nonce>.<root>` — so start/complete agree for ANY prefix.
  const colon = payload.lastIndexOf(":")
  const body = (colon >= 0 ? payload.slice(colon + 1) : payload).trim()
  const [nonce, rootFromQr] = body.split(".")
  const anon = () => makeAnonSpaceClient({ baseUrl: opts.baseUrl, namespace: opts.namespace, fetch: opts.fetch })

  const res = await anon().pull(layout.pairingPull(nonce)).catch(() => null)
  const sealed = res?.data as Record<string, unknown> | undefined
  if (!sealed || !sealed.v) throw new Error("Pairing code not found or expired.")

  let inner: Uint8Array
  try {
    inner = await openWithPassphrase(pin, sealed as never)
  } catch {
    throw new Error("Wrong PIN or corrupted pairing code.")
  }
  const parsed = JSON.parse(new TextDecoder().decode(inner)) as { keys: unknown; bundle: unknown }

  const expectedRootEdPub = opts.expectedRootEdPub ?? (rootFromQr || undefined)
  const installOpts: Parameters<typeof installPairingBundle>[2] = expectedRootEdPub
    ? { expectedRootEdPub }
    : opts.confirmUnpinnedRoot
      ? { confirmUnpinnedRoot: opts.confirmUnpinnedRoot }
      : {}
  const installed = await installPairingBundle(
    parsed.bundle as Parameters<typeof installPairingBundle>[0],
    parsed.keys as Parameters<typeof installPairingBundle>[1],
    installOpts,
  )

  // Best-effort one-shot clear: overwrite the rendezvous slot with an empty doc so
  // the PIN-sealed bundle is not left readable in the public collection. Failure is
  // harmless — the server's TTL on _pairing/* is the real backstop.
  const clear = anon()
  void clear
    .pull(layout.pairingPull(nonce))
    .then((r) => clear.push(layout.pairingPush(nonce), {} as Record<string, unknown>, r.hash))
    .catch(() => {})

  const userId = installed.credentials.userId
  return {
    userId,
    fingerprint: fingerprintFromUserId(userId),
    deviceKeys: installed.credentials.device,
    capCert: installed.credentials.capCert,
  }
}
