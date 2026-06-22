/**
 * Sealed envelopes — wrap a small secret to a single X25519 KEM key so it can
 * ride inside a *plaintext* synced document without exposing it to the server (or
 * to anyone who can read the doc but lacks the recipient's KEM private key).
 *
 * This is a thin, general-purpose layer over the keyring's single-recipient
 * primitive ({@link wrapForRecipient}). It is independent of any keyring document
 * or epoch rotation — each blob wraps a fresh content key to one static recipient
 * key — so it suits one-off sealed credentials (API tokens, OAuth secrets,
 * bearer secrets embedded in invite links, peer-to-peer hand-offs).
 *
 * Two shapes, one mechanism:
 *  - {@link sealToSelf}/{@link unsealFromSelf} — sealed to the sealer's OWN KEM
 *    key, for account secrets that must sync across a user's devices (recovered
 *    on any device holding the same KEM private key).
 *  - {@link seal}/{@link unseal} — sealed to ANOTHER identity's published KEM key,
 *    for delivering a secret to a peer through a doc they can read. The recipient
 *    trial-unseals (a wrong-recipient blob simply throws), which is exactly what
 *    lets several recipients share one carrier doc.
 *
 * Mechanism: a random AES-256 content key is wrapped to the recipient's X25519
 * KEM key via {@link wrapForRecipient} (sealer-signed, so the recipient can
 * authenticate who sealed it via `entry.addedBy`), then the payload is sealed
 * with AES-256-GCM under that content key.
 */
import { getCrypto, getBase64 } from "@drakkar.software/starfish-protocol"

import { concat } from "./_crypto_helpers.js"
import { unwrapFromEntry, verifyEntrySignature, wrapForRecipient } from "./keyring.js"
import type { WrappedKeyEntry } from "./keyring.js"

/**
 * A payload sealed to a KEM key: the wrapped content key + base64(iv ‖ ct).
 *
 * `v` is set to `1` when the blob was sealed with an AAD context string.
 * Opening a `v:1` blob without the matching AAD throws immediately (prevents
 * relocation/downgrade attacks where a blob sealed in one context is
 * replayed in another).
 */
export interface SealedBlob {
  /** The content key wrapped to the recipient's KEM key (single-recipient, sealer-signed). */
  entry: WrappedKeyEntry
  /** `base64( iv(12) ‖ AES-256-GCM(cek, iv, plaintext[, aad]) )`. */
  ct: string
  /**
   * Version marker. `1` means the blob was sealed with an AAD context binding.
   * Absent / `undefined` means the blob was sealed without AAD (legacy).
   * A consumer MUST pass the matching `aad` to unseal a `v:1` blob.
   */
  v?: 1
}

/** The sealer's Ed25519 signing keypair (hex) — signs the wrap entry for audit. */
export interface SealerKeys {
  edPrivHex: string
  edPubHex: string
}

/**
 * Every blob wraps to a single STATIC recipient key with no rotating keyring, so
 * the wrap entry lives at a fixed pseudo-epoch. {@link wrapForRecipient} and
 * {@link verifyEntrySignature} must agree on it (it is bound into `addedSig`).
 */
const SEAL_EPOCH = 0
const IV_BYTES = 12
const AES_ALGO = "AES-GCM"
const ENC = new TextEncoder()
const DEC = new TextDecoder()
// Exported for use in tests and cross-language serialisation verification.
export const _SEAL_EPOCH = SEAL_EPOCH

function toBytes(plaintext: Uint8Array | string): Uint8Array {
  return typeof plaintext === "string" ? ENC.encode(plaintext) : plaintext
}

/**
 * Seal `plaintext` to `recipientKemPubHex`, signed by `sealer`. Only the holder
 * of the recipient KEM private key can open the result. `plaintext` may be raw
 * bytes or a UTF-8 string.
 *
 * @param aad  Optional Additional Authenticated Data string. When provided, the
 *             AES-GCM encryption binds `aad` into the authentication tag and the
 *             returned blob has `v:1` set. An `unseal` (or `unsealToString`,
 *             `unsealFromSelf`) call that does NOT supply the matching `aad` throws
 *             immediately, before any crypto — preventing relocation/downgrade
 *             attacks where a blob sealed in one context is replayed in another.
 *             `aad` is NOT stored in the blob and is never transmitted to the
 *             server; both sealer and opener must agree on it out-of-band.
 */
export async function seal(
  plaintext: Uint8Array | string,
  recipientKemPubHex: string,
  sealer: SealerKeys,
  aad?: string,
): Promise<SealedBlob> {
  const crypto = getCrypto()
  const cek = crypto.getRandomValues(new Uint8Array(32))
  const entry = await wrapForRecipient(cek, recipientKemPubHex, {
    adderEdPrivHex: sealer.edPrivHex,
    adderEdPubHex: sealer.edPubHex,
    addedAt: Math.floor(Date.now() / 1000),
    epoch: SEAL_EPOCH,
  })
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const key = await crypto.subtle.importKey("raw", cek as BufferSource, { name: AES_ALGO }, false, ["encrypt"])
  const encParams: AesGcmParams = aad
    ? { name: AES_ALGO, iv: iv as BufferSource, additionalData: ENC.encode(aad) as BufferSource }
    : { name: AES_ALGO, iv: iv as BufferSource }
  const ctBuf = await crypto.subtle.encrypt(encParams, key, toBytes(plaintext) as BufferSource)
  const blob: SealedBlob = { entry, ct: getBase64().encode(concat(iv, new Uint8Array(ctBuf))) }
  if (aad) blob.v = 1
  return blob
}

/**
 * Seal `plaintext` so only the holder of `selfKemPubHex`'s private key (the
 * sealer's own account, across its devices) can open it.
 *
 * Pass `aad` to enable context-binding — see {@link seal} for full semantics.
 */
export function sealToSelf(
  plaintext: Uint8Array | string,
  selfKemPubHex: string,
  sealer: SealerKeys,
  aad?: string,
): Promise<SealedBlob> {
  return seal(plaintext, selfKemPubHex, sealer, aad)
}

async function open(blob: SealedBlob, recipientKemPrivHex: string, aad?: string): Promise<Uint8Array> {
  const cek = await unwrapFromEntry(blob.entry, recipientKemPrivHex)
  const packed = getBase64().decode(blob.ct)
  if (packed.length < IV_BYTES) throw new Error("sealed blob shorter than the IV length")
  // Fresh ArrayBuffer-backed copies so the views satisfy WebCrypto's BufferSource.
  const iv = new Uint8Array(packed.subarray(0, IV_BYTES))
  const ct = new Uint8Array(packed.subarray(IV_BYTES))
  const key = await getCrypto().subtle.importKey("raw", new Uint8Array(cek) as BufferSource, { name: AES_ALGO }, false, ["decrypt"])
  const decParams: AesGcmParams = aad
    ? { name: AES_ALGO, iv: iv as BufferSource, additionalData: ENC.encode(aad) as BufferSource }
    : { name: AES_ALGO, iv: iv as BufferSource }
  const out = await getCrypto().subtle.decrypt(decParams, key, ct as BufferSource)
  return new Uint8Array(out)
}

/**
 * Open a {@link SealedBlob} sealed to the holder of `recipientKemPrivHex`. Always
 * verifies the wrap entry's signature so `entry.addedBy` is an authentic claim of
 * who sealed it. Pass `opts.requireSealer` (an Ed25519 pubkey hex) to additionally
 * PIN the sealer — the open throws unless the blob was signed by that key. Without
 * it, any peer may have sealed to us (the `addedBy` is reported but not pinned),
 * which is the trial-unseal mode for a shared carrier doc.
 *
 * Pass `opts.aad` when the blob was sealed with a context string (i.e. `blob.v ===
 * 1`). Opening a `v:1` blob without the matching `aad` throws immediately — this
 * is the downgrade/relocation-attack guard.
 *
 * Throws when the blob was sealed to a different recipient (wrong key), when the
 * signature is invalid, when a required sealer doesn't match, or on AEAD failure.
 */
export async function unseal(
  blob: SealedBlob,
  recipientKemPrivHex: string,
  opts: { requireSealer?: string; aad?: string } = {},
): Promise<Uint8Array> {
  // v:1 blobs were sealed with context AAD — reject any open that lacks it.
  // This must happen BEFORE any crypto to prevent timing-side-channel leaks.
  if (blob.v === 1 && !opts.aad) {
    throw new Error(
      "aad required: this blob (v:1) was sealed with context-binding — pass the matching aad to open it",
    )
  }
  if (!(await verifyEntrySignature(blob.entry, SEAL_EPOCH))) throw new Error("sealed blob signature invalid")
  if (opts.requireSealer !== undefined && blob.entry.addedBy !== opts.requireSealer) {
    throw new Error("sealed blob not signed by the required sealer")
  }
  return open(blob, recipientKemPrivHex, opts.aad)
}

/**
 * {@link unseal} decoding the plaintext as a UTF-8 string.
 *
 * Pass `opts.aad` for `v:1` blobs — see {@link unseal}.
 */
export async function unsealToString(
  blob: SealedBlob,
  recipientKemPrivHex: string,
  opts: { requireSealer?: string; aad?: string } = {},
): Promise<string> {
  return DEC.decode(await unseal(blob, recipientKemPrivHex, opts))
}

/**
 * Open a blob produced by {@link sealToSelf}: pins the sealer to the account's own
 * Ed key (defense-in-depth — only our own self-seal is trusted; a substituted
 * entry that wraps an attacker-chosen key to our public KEM key is rejected up
 * front). `self.kemPrivHex` opens it; `self.edPubHex` is the required sealer.
 *
 * Pass `opts.aad` when the blob was sealed with a context string (`v:1`).
 */
export function unsealFromSelf(
  blob: SealedBlob,
  self: { kemPrivHex: string; edPubHex: string },
  opts: { aad?: string } = {},
): Promise<Uint8Array> {
  return unseal(blob, self.kemPrivHex, { requireSealer: self.edPubHex, aad: opts.aad })
}
