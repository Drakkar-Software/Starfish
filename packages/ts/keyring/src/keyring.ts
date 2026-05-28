/**
 * v3.0 multi-recipient keyring with delegated encryption.
 *
 * Each `WrappedKeyEntry` uses per-entry ephemeral X25519 ECDH (HPKE-DHKEM-style):
 *
 *     shared  = X25519(ephPriv, recipient.subKem)
 *     wrapKey = HKDF-SHA256(shared, salt="starfish-wrap", info="starfish-wrap")
 *     ct      = base64(iv || AES-256-GCM(wrapKey, iv, cek))
 *     addedSig = base64( Ed25519(adder.priv, stableStringify(canonical)) )
 *
 * Starfish speaks ed25519 only on the wire — the keyring entry carries no suite
 * discriminator. Recipients are identified by exact `subKem` match.
 *
 * This module replaces the removed v2 `group-crypto.ts` (deleted in 3.0): the
 * per-collection delegated keyring is the only encryption surface.
 */

import {
  getCrypto,
  getBase64,
  stableStringify,
  ed25519Suite,
} from "@drakkar.software/starfish-protocol"

import { bytesToHex, concat, hkdfBytes } from "./_crypto_helpers.js"

// ── Locked protocol constants ─────────────────────────────────────────────────

const ENC = new TextEncoder()

/** HKDF salt for wrap-key derivation. Locked by the cross-language vector. */
export const KEYRING_WRAP_SALT: Uint8Array = ENC.encode("starfish-wrap")
/** HKDF info for wrap-key derivation. Locked by the cross-language vector. */
export const KEYRING_WRAP_INFO: Uint8Array = ENC.encode("starfish-wrap")
/** AES-GCM IV length used by the wrap layer. */
export const KEYRING_IV_BYTES = 12

const AES_ALGO = "AES-GCM"

/** Big-endian u32 epoch header prepended to a sealed blob. */
function epochHeader(epoch: number): Uint8Array {
  const h = new Uint8Array(4)
  h[0] = (epoch >>> 24) & 0xff
  h[1] = (epoch >>> 16) & 0xff
  h[2] = (epoch >>> 8) & 0xff
  h[3] = epoch & 0xff
  return h
}

/** Read the big-endian u32 epoch header from the front of a sealed blob. */
function readEpochHeader(blob: Uint8Array): number {
  return ((blob[0]! << 24) | (blob[1]! << 16) | (blob[2]! << 8) | blob[3]!) >>> 0
}

/** Additional authenticated data binding a sealed blob to its epoch + storage path. */
function blobAad(epoch: number, aad: string | undefined): Uint8Array {
  return ENC.encode(`starfish-blob:${epoch}:${aad ?? ""}`)
}

// ── Types ─────────────────────────────────────────────────────────────────────

/** A single recipient's wrapped CEK, with audit signature from the adder. */
export interface WrappedKeyEntry {
  /** Recipient X25519 KEM pubkey (hex). Identifies the recipient by exact match. */
  subKem: string
  /** Ephemeral X25519 KEM pubkey for this entry (hex). */
  ephKem: string
  /** `base64(iv || AES-GCM(wrapKey, iv, cek))`. */
  ct: string
  /** Adder's Ed25519 signing pubkey (hex). */
  addedBy: string
  /** Ed25519 signature over the canonical signing input, base64. */
  addedSig: string
  /** Unix seconds when the entry was added. */
  addedAt: number
}

/** All recipients with access to a given CEK epoch. */
export interface KeyringEpoch {
  wrappedKeys: WrappedKeyEntry[]
  createdAt: number
}

/** Full keyring document, suitable for pushing to a Starfish collection. */
export interface Keyring {
  v: 1
  currentEpoch: number
  epochs: Record<string, KeyringEpoch>
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function importAesKey(rawKeyBytes: Uint8Array): Promise<CryptoKey> {
  const subtle = getCrypto().subtle
  return subtle.importKey(
    "raw",
    rawKeyBytes as BufferSource,
    AES_ALGO,
    false,
    ["encrypt", "decrypt"],
  )
}

function randomBytes(n: number): Uint8Array {
  return getCrypto().getRandomValues(new Uint8Array(n))
}

/**
 * Canonical signing input for an `addedSig`. Stable-stringify of
 * {addedAt, addedBy, ct, ephKem, epoch, subKem}. Locked by the cross-language
 * wrap vector — byte-identical across TS and Python.
 */
function canonicalAddedSigInput(args: {
  addedAt: number
  addedBy: string
  ct: string
  ephKem: string
  epoch: number
  subKem: string
}): string {
  return stableStringify({
    addedAt: args.addedAt,
    addedBy: args.addedBy,
    ct: args.ct,
    ephKem: args.ephKem,
    epoch: args.epoch,
    subKem: args.subKem,
  })
}

// ── Core wrap / unwrap ────────────────────────────────────────────────────────

/**
 * Wraps a CEK for a single recipient using ephemeral X25519 ECDH.
 *
 * Generates a fresh ephemeral X25519 keypair (or uses `opts.ephPriv` if provided,
 * useful for reproducible vectors), runs X25519 ECDH with the recipient's KEM
 * pubkey, derives the wrap key via HKDF-SHA256, and encrypts the CEK with
 * AES-256-GCM. The adder signs the entry with Ed25519 for audit.
 */
export async function wrapForRecipient(
  cek: Uint8Array,
  recipientKemPubHex: string,
  opts: {
    adderEdPrivHex: string
    adderEdPubHex: string
    addedAt: number
    epoch: number
    ephPriv?: Uint8Array
    iv?: Uint8Array
  },
): Promise<WrappedKeyEntry> {
  const ephPrivHex = opts.ephPriv
    ? bytesToHex(opts.ephPriv)
    : ed25519Suite.generateKemKeypair().privHex
  const ephKemHex = ed25519Suite.kemPublic(ephPrivHex)

  // deriveSharedSecret asserts a usable (non-degenerate) secret, fail closed.
  const shared = ed25519Suite.deriveSharedSecret(ephPrivHex, recipientKemPubHex)
  const wrapKeyBytes = await hkdfBytes(shared, KEYRING_WRAP_SALT, KEYRING_WRAP_INFO, 32)
  const wrapKey = await importAesKey(wrapKeyBytes)

  const iv = opts.iv ?? randomBytes(KEYRING_IV_BYTES)
  const subtle = getCrypto().subtle
  const ctBuf = await subtle.encrypt({ name: AES_ALGO, iv: iv as BufferSource }, wrapKey, cek as BufferSource)
  const combined = concat(iv, new Uint8Array(ctBuf))
  const ctB64 = getBase64().encode(combined)

  const canonical = canonicalAddedSigInput({
    addedAt: opts.addedAt,
    addedBy: opts.adderEdPubHex,
    ct: ctB64,
    ephKem: ephKemHex,
    epoch: opts.epoch,
    subKem: recipientKemPubHex,
  })
  const sigBytes = ed25519Suite.sign(ENC.encode(canonical), opts.adderEdPrivHex)
  const addedSig = getBase64().encode(sigBytes)

  // Best-effort wipe of secret intermediates before returning.
  shared.fill(0)
  wrapKeyBytes.fill(0)

  return {
    subKem: recipientKemPubHex,
    ephKem: ephKemHex,
    ct: ctB64,
    addedBy: opts.adderEdPubHex,
    addedSig,
    addedAt: opts.addedAt,
  }
}

/**
 * Recovers the CEK from a `WrappedKeyEntry` using the recipient's X25519 private key.
 *
 * Throws if AES-GCM authentication fails (wrong key, tampered ciphertext).
 *
 * SECURITY: this is a low-level primitive — it does NOT verify the entry's
 * `addedSig` or check `addedBy` provenance. The `addedSig` is self-attesting, so
 * a hostile server can hand you an entry that wraps an attacker-chosen CEK to
 * your (public) KEM key and self-signs it. Before trusting an entry fetched from
 * an untrusted server, call {@link verifyEntrySignature} and confirm `addedBy`
 * is in your `trustedAdders` set (the high-level `recoverCurrentCek` /
 * `createKeyringEncryptor` / `listRecipients` paths already do this).
 */
export async function unwrapFromEntry(
  entry: WrappedKeyEntry,
  recipientKemPrivHex: string,
): Promise<Uint8Array> {
  const shared = ed25519Suite.deriveSharedSecret(recipientKemPrivHex, entry.ephKem)
  const wrapKeyBytes = await hkdfBytes(shared, KEYRING_WRAP_SALT, KEYRING_WRAP_INFO, 32)
  const wrapKey = await importAesKey(wrapKeyBytes)

  const combined = getBase64().decode(entry.ct)
  if (combined.length < KEYRING_IV_BYTES) {
    throw new Error("Wrapped entry ciphertext is shorter than the IV length")
  }
  const iv = combined.slice(0, KEYRING_IV_BYTES)
  const ct = combined.slice(KEYRING_IV_BYTES)
  try {
    const ptBuf = await getCrypto().subtle.decrypt(
      { name: AES_ALGO, iv: iv as BufferSource },
      wrapKey,
      ct as BufferSource,
    )
    return new Uint8Array(ptBuf)
  } catch (err) {
    throw new Error("Failed to unwrap CEK: AES-GCM authentication failed", { cause: err })
  }
}

/**
 * Verifies the audit signature on a wrapped key entry. Recomputes the canonical
 * signing input from the entry fields and the given epoch, then checks the
 * Ed25519 signature against `entry.addedBy`.
 */
export async function verifyEntrySignature(entry: WrappedKeyEntry, epoch: number): Promise<boolean> {
  const canonical = canonicalAddedSigInput({
    addedAt: entry.addedAt,
    addedBy: entry.addedBy,
    ct: entry.ct,
    ephKem: entry.ephKem,
    epoch,
    subKem: entry.subKem,
  })
  try {
    const sig = getBase64().decode(entry.addedSig)
    return ed25519Suite.verify(sig, ENC.encode(canonical), entry.addedBy)
  } catch {
    return false
  }
}

// ── Keyring lifecycle ─────────────────────────────────────────────────────────

/**
 * Creates a brand-new keyring at epoch 1 wrapping a CEK for every recipient.
 * Generates a random 32-byte CEK if none is provided.
 */
export async function createKeyring(
  adder: { edPrivHex: string; edPubHex: string },
  recipients: { subKemHex: string }[],
  cek?: Uint8Array,
  addedAt: number = Math.floor(Date.now() / 1000),
): Promise<{ keyring: Keyring; cek: Uint8Array }> {
  const resolvedCek = cek ?? randomBytes(32)
  const wrappedKeys: WrappedKeyEntry[] = []
  for (const r of recipients) {
    wrappedKeys.push(
      await wrapForRecipient(resolvedCek, r.subKemHex, {
        adderEdPrivHex: adder.edPrivHex,
        adderEdPubHex: adder.edPubHex,
        addedAt,
        epoch: 1,
      }),
    )
  }
  const keyring: Keyring = {
    v: 1,
    currentEpoch: 1,
    epochs: {
      "1": { wrappedKeys, createdAt: addedAt },
    },
  }
  return { keyring, cek: resolvedCek }
}

/**
 * Appends a new recipient to the current epoch. The adder must supply the
 * current CEK so it can wrap it for the newcomer. Throws if a recipient with
 * the same `subKem` is already present in the current epoch.
 *
 * Note — the newcomer is wrapped into the CURRENT epoch ONLY. Documents sealed
 * under an EARLIER epoch (e.g. before a revoke rotated the epoch) stay
 * unreadable to them, surfacing as "No key available for epoch N" on decrypt.
 * To share existing content, re-seal it at the current epoch (decrypt with a
 * recipient that holds the old CEK, then re-encrypt) after adding them.
 */
export async function addRecipient(
  keyring: Keyring,
  adder: { edPrivHex: string; edPubHex: string },
  currentCek: Uint8Array,
  recipientKemHex: string,
  addedAt: number = Math.floor(Date.now() / 1000),
): Promise<Keyring> {
  const epochKey = String(keyring.currentEpoch)
  const epoch = keyring.epochs[epochKey]
  if (!epoch) throw new Error(`Epoch ${keyring.currentEpoch} not found in keyring`)
  if (epoch.wrappedKeys.some((e) => e.subKem === recipientKemHex)) {
    throw new Error(`Recipient ${recipientKemHex} already present in epoch ${keyring.currentEpoch}`)
  }

  const entry = await wrapForRecipient(currentCek, recipientKemHex, {
    adderEdPrivHex: adder.edPrivHex,
    adderEdPubHex: adder.edPubHex,
    addedAt,
    epoch: keyring.currentEpoch,
  })
  return {
    ...keyring,
    epochs: {
      ...keyring.epochs,
      [epochKey]: {
        ...epoch,
        wrappedKeys: [...epoch.wrappedKeys, entry],
      },
    },
  }
}

/**
 * Mints a new CEK and appends a new epoch (`currentEpoch + 1`) wrapping the
 * fresh CEK for the retained recipients. Old epochs are preserved unchanged
 * so existing documents stay decryptable for whoever still has those keys.
 */
export async function rotateEpoch(
  keyring: Keyring,
  adder: { edPrivHex: string; edPubHex: string },
  retainedRecipients: { subKemHex: string }[],
  addedAt: number = Math.floor(Date.now() / 1000),
): Promise<{ keyring: Keyring; cek: Uint8Array }> {
  const newEpoch = keyring.currentEpoch + 1
  const newCek = randomBytes(32)
  const wrappedKeys: WrappedKeyEntry[] = []
  for (const r of retainedRecipients) {
    wrappedKeys.push(
      await wrapForRecipient(newCek, r.subKemHex, {
        adderEdPrivHex: adder.edPrivHex,
        adderEdPubHex: adder.edPubHex,
        addedAt,
        epoch: newEpoch,
      }),
    )
  }
  const next: Keyring = {
    ...keyring,
    currentEpoch: newEpoch,
    epochs: {
      ...keyring.epochs,
      [String(newEpoch)]: { wrappedKeys, createdAt: addedAt },
    },
  }
  return { keyring: next, cek: newCek }
}

// ── Encryptor factory ─────────────────────────────────────────────────────────

/**
 * Encryptor whose payloads carry the epoch they were sealed under. Decrypt
 * locates the entry for the recipient and unwraps the matching epoch's CEK
 * (cached after first use).
 */
export interface KeyringEncryptor {
  /** Encrypt arbitrary JSON-serializable data with the current epoch's CEK. */
  encrypt(data: object): Promise<{ _encrypted: string; _epoch: number }>
  /** Decrypt a payload sealed under any epoch the recipient has access to. */
  decrypt(payload: { _encrypted: string; _epoch?: number }): Promise<object>
  /**
   * Seal raw bytes under the current epoch as a self-describing blob —
   * `[u32 BE epoch][12-byte iv][AES-256-GCM ciphertext‖tag]` — suitable for
   * storing directly via the client's `pushBlob`. The epoch and the caller's
   * `aad` (e.g. the blob's storage path) are bound into the GCM tag so a hostile
   * server cannot relocate the blob to another path or replay it at a different
   * epoch. Use for large binary payloads (attachments) the JSON `encrypt` path
   * would otherwise have to base64-inflate.
   */
  sealBytes(bytes: Uint8Array, aad?: string): Promise<Uint8Array>
  /** Open a blob produced by {@link sealBytes}, verifying the bound `aad`. */
  openBytes(blob: Uint8Array, aad?: string): Promise<Uint8Array>
}

/**
 * Returns a `KeyringEncryptor` for the given recipient. Pre-unwraps the CEK
 * for every epoch the recipient appears in; falls back to `currentEpoch` when
 * a payload omits `_epoch` (matches v2 behavior).
 *
 * Security — the keyring document is fetched from an untrusted server, so the
 * encryptor refuses to adopt CEK material it cannot vouch for:
 *
 *  - **Duplicate `subKem` ⇒ tampering.** A well-formed epoch has at most one
 *    entry per recipient (enforced on write by {@link addRecipient}). If the
 *    recipient's `subKem` appears more than once in an epoch — e.g. a hostile
 *    server injected an extra entry wrapping an attacker-chosen CEK — the
 *    epoch is skipped (fail closed) rather than picking one by position.
 *  - **`opts.trustedAdders` (recommended).** The `addedSig` audit signature is
 *    *self-attesting*: it only proves "whoever owns `addedBy` signed this
 *    entry", which any attacker satisfies for their own forgery. Pass the set
 *    of Ed25519 pubkeys (hex) you trust to grant access (e.g. the collection
 *    owner's root key). Entries added by anyone else are skipped. When omitted,
 *    provenance is NOT verified — only the duplicate-`subKem` and signature
 *    self-consistency checks apply, so a server that *replaces* an entry can
 *    still substitute a CEK. Supply `trustedAdders` for end-to-end safety.
 *
 * Other verification failures (bad `addedSig`, unwrap failure) are skipped with
 * a logged warning rather than thrown, so one corrupted entry does not lock the
 * recipient out of other epochs.
 *
 * Throws if the recipient has no usable entry in `currentEpoch`.
 */
export async function createKeyringEncryptor(
  keyring: Keyring,
  recipient: { kemPubHex: string; kemPrivHex: string },
  opts: { trustedAdders?: string[]; minEpoch?: number } = {},
): Promise<KeyringEncryptor> {
  if (!opts.trustedAdders || opts.trustedAdders.length === 0) {
    throw new Error(
      "createKeyringEncryptor: `trustedAdders` is required — pass the Ed25519 pubkey(s) " +
        "you trust to grant keyring access (e.g. the collection owner's root key). " +
        "Without it a hostile server could substitute a wrapped-key entry (the addedSig is self-attesting).",
    )
  }
  if (opts.minEpoch !== undefined && keyring.currentEpoch < opts.minEpoch) {
    throw new Error(
      `createKeyringEncryptor: keyring epoch ${keyring.currentEpoch} is below the last-seen ` +
        `epoch ${opts.minEpoch} — possible rollback by a hostile server; refusing to adopt a stale keyring.`,
    )
  }
  const trustedAdders = new Set(opts.trustedAdders)
  const epochCeks = new Map<number, Uint8Array>()
  for (const [epochStr, epoch] of Object.entries(keyring.epochs)) {
    const matches = epoch.wrappedKeys.filter((e) => e.subKem === recipient.kemPubHex)
    if (matches.length === 0) continue
    const epochNum = parseInt(epochStr, 10)
    if (matches.length > 1) {
      console.warn(
        `[starfish:keyring] skipping epoch ${epochNum} for recipient ${recipient.kemPubHex}: ${matches.length} entries share this subKem (tampering)`,
      )
      continue
    }
    const entry = matches[0]!
    if (!trustedAdders.has(entry.addedBy)) {
      console.warn(
        `[starfish:keyring] skipping epoch ${epochNum} for recipient ${recipient.kemPubHex}: addedBy ${entry.addedBy} is not a trusted adder`,
      )
      continue
    }
    const sigOk = await verifyEntrySignature(entry, epochNum)
    if (!sigOk) {
      console.warn(
        `[starfish:keyring] skipping epoch ${epochNum} for recipient ${recipient.kemPubHex}: addedSig verification failed`,
      )
      continue
    }
    try {
      const cek = await unwrapFromEntry(entry, recipient.kemPrivHex)
      epochCeks.set(epochNum, cek)
    } catch {
      // skip epochs we can't unwrap — recipient was added later or wrong key
    }
  }

  const currentEpoch = keyring.currentEpoch
  const currentCek = epochCeks.get(currentEpoch)
  if (!currentCek) {
    throw new Error(
      `No wrapped key for recipient ${recipient.kemPubHex} in current epoch ${currentEpoch}`,
    )
  }

  const aesKeyCache = new Map<number, Promise<CryptoKey>>()
  function aesKeyFor(epoch: number): Promise<CryptoKey> {
    const cached = aesKeyCache.get(epoch)
    if (cached) return cached
    const cek = epochCeks.get(epoch)
    if (!cek) {
      return Promise.reject(
        new Error(
          `No key available for epoch ${epoch}: recipient ${recipient.kemPubHex} joined the keyring in a later epoch (e.g. after a rotation) and can't read content sealed earlier — re-seal it at the current epoch to grant access`,
        ),
      )
    }
    const promise = importAesKey(cek)
    aesKeyCache.set(epoch, promise)
    return promise
  }

  return {
    async encrypt(data: object): Promise<{ _encrypted: string; _epoch: number }> {
      const key = await aesKeyFor(currentEpoch)
      const iv = randomBytes(KEYRING_IV_BYTES)
      const plaintext = ENC.encode(JSON.stringify(data))
      const ctBuf = await getCrypto().subtle.encrypt(
        { name: AES_ALGO, iv: iv as BufferSource },
        key,
        plaintext as BufferSource,
      )
      const combined = concat(iv, new Uint8Array(ctBuf))
      return { _encrypted: getBase64().encode(combined), _epoch: currentEpoch }
    },

    async decrypt(payload: { _encrypted: string; _epoch?: number }): Promise<object> {
      const epoch = typeof payload._epoch === "number" ? payload._epoch : currentEpoch
      const key = await aesKeyFor(epoch)
      const combined = getBase64().decode(payload._encrypted)
      if (combined.length < KEYRING_IV_BYTES) {
        throw new Error("Encrypted payload is too short")
      }
      const iv = combined.slice(0, KEYRING_IV_BYTES)
      const ct = combined.slice(KEYRING_IV_BYTES)
      try {
        const ptBuf = await getCrypto().subtle.decrypt(
          { name: AES_ALGO, iv: iv as BufferSource },
          key,
          ct as BufferSource,
        )
        return JSON.parse(new TextDecoder().decode(ptBuf)) as object
      } catch (err) {
        throw new Error("Decryption failed: payload may be tampered or epoch CEK is wrong", {
          cause: err,
        })
      }
    },

    async sealBytes(bytes: Uint8Array, aad?: string): Promise<Uint8Array> {
      const key = await aesKeyFor(currentEpoch)
      const iv = randomBytes(KEYRING_IV_BYTES)
      const ctBuf = await getCrypto().subtle.encrypt(
        { name: AES_ALGO, iv: iv as BufferSource, additionalData: blobAad(currentEpoch, aad) as BufferSource },
        key,
        bytes as BufferSource,
      )
      return concat(epochHeader(currentEpoch), iv, new Uint8Array(ctBuf))
    },

    async openBytes(blob: Uint8Array, aad?: string): Promise<Uint8Array> {
      if (blob.length < 4 + KEYRING_IV_BYTES) {
        throw new Error("openBytes: blob shorter than its epoch+iv header")
      }
      const epoch = readEpochHeader(blob)
      const key = await aesKeyFor(epoch)
      const iv = blob.slice(4, 4 + KEYRING_IV_BYTES)
      const ct = blob.slice(4 + KEYRING_IV_BYTES)
      try {
        const ptBuf = await getCrypto().subtle.decrypt(
          { name: AES_ALGO, iv: iv as BufferSource, additionalData: blobAad(epoch, aad) as BufferSource },
          key,
          ct as BufferSource,
        )
        return new Uint8Array(ptBuf)
      } catch (err) {
        throw new Error("openBytes: decryption failed — tampered, wrong epoch CEK, or AAD mismatch", {
          cause: err,
        })
      }
    },
  }
}
