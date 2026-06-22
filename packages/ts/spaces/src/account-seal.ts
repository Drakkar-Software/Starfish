/**
 * Session-scoped sealed-envelope helpers.
 *
 * Wraps a small secret to an X25519 KEM key so it can ride in a plaintext
 * synced document without exposing it to the server.
 *
 *  - {@link sealToSelf}/{@link unsealFromSelf} — sealed to THIS session's own
 *    KEM key (e.g. link-access bearer credentials in `_spaces.pubAccess`).
 *    Recoverable on any device sharing the same root identity.
 *  - {@link sealToRecipient}/{@link unsealFromRecipient} — sealed to ANOTHER
 *    user's published KEM key (inbox delivery of invite bundles, grants, etc.).
 *
 * Wire format: `ct` is hex-encoded `iv[12] ‖ AES-256-GCM ciphertext`.
 *
 * Functions accept any object with a `keys` field (a `Session` or a plain
 * `{ keys: DeviceKeys }` wrapper) so callers need not destructure the session.
 */
import { bytesToHex, hexToBytes, unwrapFromEntry, verifyEntrySignature, wrapForRecipient } from "@drakkar.software/starfish-keyring"

import type { SealedBlob } from "./config.js"
import type { DeviceKeys } from "./client.js"

export type { SealedBlob }

/** Minimal structural type accepted by all seal/unseal functions. */
export interface HasKeys {
  keys: DeviceKeys
}

const SELF_EPOCH = 0

const subtle = () => globalThis.crypto.subtle

async function sealRaw(
  session: HasKeys,
  recipientKemPub: string,
  plaintext: string,
  aad?: string,
): Promise<SealedBlob> {
  const keys = session.keys
  const cek = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const entry = await wrapForRecipient(cek, recipientKemPub, {
    adderEdPrivHex: keys.edPriv,
    adderEdPubHex: keys.edPub,
    addedAt: Math.floor(Date.now() / 1000),
    epoch: SELF_EPOCH,
  })
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const key = await subtle().importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"])
  const encParams: AesGcmParams = aad
    ? { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }
    : { name: "AES-GCM", iv }
  const ctBuf = await subtle().encrypt(encParams, key, new TextEncoder().encode(plaintext))
  const packed = new Uint8Array(iv.length + ctBuf.byteLength)
  packed.set(iv, 0)
  packed.set(new Uint8Array(ctBuf), iv.length)
  const blob: SealedBlob = { entry: entry as unknown as SealedBlob["entry"], ct: bytesToHex(packed) }
  if (aad) blob.v = 1
  return blob
}

async function openRaw(session: HasKeys, blob: SealedBlob, aad?: string): Promise<string> {
  const keys = session.keys
  // v:1 blobs require matching AAD — reject early to prevent relocation attacks.
  if (blob.v === 1 && !aad) {
    throw new Error(
      "aad required: this blob (v:1) was sealed with context binding — pass the matching aad to open it.",
    )
  }
  const cek = await unwrapFromEntry(blob.entry as unknown as Parameters<typeof unwrapFromEntry>[0], keys.kemPriv)
  const packed = hexToBytes(blob.ct)
  const iv = new Uint8Array(packed.subarray(0, 12))
  const ctBytes = new Uint8Array(packed.subarray(12))
  const key = await subtle().importKey("raw", new Uint8Array(cek), { name: "AES-GCM" }, false, ["decrypt"])
  const decParams: AesGcmParams = aad
    ? { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }
    : { name: "AES-GCM", iv }
  const out = await subtle().decrypt(decParams, key, ctBytes)
  return new TextDecoder().decode(out)
}

// ── Public API ─────────────────────────────────────────────────────────────────

/** Seal `plaintext` to this account's own KEM key (cross-device recovery). */
export function sealToSelf(session: HasKeys, plaintext: string, aad?: string): Promise<SealedBlob> {
  return sealRaw(session, session.keys.kemPub, plaintext, aad)
}

/**
 * Open a blob created by {@link sealToSelf}.
 * Enforces that the blob was self-signed (entry.addedBy === edPub).
 */
export async function unsealFromSelf(session: HasKeys, blob: SealedBlob, aad?: string): Promise<string> {
  if (blob.entry.addedBy !== session.keys.edPub) throw new Error("sealed blob not self-signed")
  if (!(await verifyEntrySignature(blob.entry as unknown as Parameters<typeof verifyEntrySignature>[0], SELF_EPOCH))) {
    throw new Error("sealed blob signature invalid")
  }
  return openRaw(session, blob, aad)
}

/** Seal `plaintext` to ANOTHER user's KEM key (inbox delivery). */
export function sealToRecipient(
  session: HasKeys,
  recipientKemPub: string,
  plaintext: string,
  aad?: string,
): Promise<SealedBlob> {
  return sealRaw(session, recipientKemPub, plaintext, aad)
}

/**
 * Open a {@link SealedBlob} sealed to THIS account by any sender.
 * Verifies the entry signature but does NOT pin the sender.
 */
export async function unsealFromRecipient(session: HasKeys, blob: SealedBlob, aad?: string): Promise<string> {
  if (!(await verifyEntrySignature(blob.entry as unknown as Parameters<typeof verifyEntrySignature>[0], SELF_EPOCH))) {
    throw new Error("sealed blob signature invalid")
  }
  return openRaw(session, blob, aad)
}
