/**
 * v3.0 multi-recipient keyring with delegated encryption.
 *
 * Each `WrappedKeyEntry` uses per-entry ephemeral ECDH (HPKE-DHKEM-style),
 * dispatched by the recipient's KEM suite (`kemAlg`):
 *
 *     shared  = suite(kemAlg).deriveSharedSecret(ephPriv, recipient.kemPub)
 *     wrapKey = HKDF-SHA256(shared, salt="starfish-wrap", info=wrapInfo(kemAlg))
 *     ct      = base64(iv || AES-256-GCM(wrapKey, iv, cek))
 *     addedSig = base64( suite(addedByAlg).sign(adder.priv, stableStringify(canonical)) )
 *
 * `kemAlg` / `addedByAlg` are optional and default to `ed25519` (tolerant
 * reader); both are folded into the `addedSig` canonical input ONLY when present
 * so an `ed25519` entry is byte-identical to the pre-suite format (the existing
 * cross-language wrap vector is the no-drift proof). Recipients are identified
 * by exact `subKem` match (for a same-suite secp256k1 recipient, `subKem` is
 * their one secp256k1 key — see `recipientKem` in the protocol package).
 *
 * This module replaces the removed v2 `group-crypto.ts` (deleted in 3.0): the
 * per-collection delegated keyring is the only encryption surface.
 */

import {
  DEFAULT_ALG,
  getCrypto,
  getBase64,
  getSuite,
  stableStringify,
  type Alg,
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
  /** Recipient KEM pubkey (hex) of suite `kemAlg`. Identifies the recipient by exact match. */
  subKem: string
  /** Ephemeral KEM pubkey for this entry (hex), of suite `kemAlg`. */
  ephKem: string
  /** `base64(iv || AES-GCM(wrapKey, iv, cek))`. */
  ct: string
  /** Adder's signing pubkey (hex), of suite `addedByAlg`. */
  addedBy: string
  /** Signature over the canonical signing input under `addedByAlg`, base64. */
  addedSig: string
  /** Unix seconds when the entry was added. */
  addedAt: number
  /**
   * Recipient KEM suite (governs `subKem`/`ephKem` and which ECDH runs).
   * Optional; absent ⇒ `ed25519` (X25519). Folded into `addedSig` when present.
   */
  kemAlg?: Alg
  /**
   * Adder's signing suite (governs `addedBy`/`addedSig`). Optional; absent ⇒
   * `ed25519`. Folded into `addedSig` when present.
   */
  addedByAlg?: Alg
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
 * Canonical signing input for an `addedSig`. Stable-stringify of {addedAt,
 * addedBy, ct, ephKem, epoch, subKem}, plus `kemAlg` / `addedByAlg` **only when
 * present**. The tolerant-reader rule: an `ed25519`/X25519 entry omits both, so
 * its canonical input is byte-identical to the pre-suite format (the existing
 * cross-language wrap vector is the regression proof). Stripping a present tag
 * changes these bytes ⇒ `addedSig` fails ⇒ fail closed (downgrade caught).
 */
function canonicalAddedSigInput(args: {
  addedAt: number
  addedBy: string
  ct: string
  ephKem: string
  epoch: number
  subKem: string
  kemAlg?: Alg
  addedByAlg?: Alg
}): string {
  const obj: Record<string, unknown> = {
    addedAt: args.addedAt,
    addedBy: args.addedBy,
    ct: args.ct,
    ephKem: args.ephKem,
    epoch: args.epoch,
    subKem: args.subKem,
  }
  if (args.kemAlg !== undefined) obj.kemAlg = args.kemAlg
  if (args.addedByAlg !== undefined) obj.addedByAlg = args.addedByAlg
  return stableStringify(obj)
}

/**
 * HKDF `info` for the wrap-key derivation, domain-separated per KEM suite. The
 * `ed25519`/X25519 value (`"starfish-wrap"`) is **frozen by the existing
 * cross-language vector and must not change**; other suites get a distinct info
 * so a shared secret from one curve can never derive the same wrap key as
 * another.
 */
function wrapInfo(kemAlg: Alg): Uint8Array {
  return kemAlg === "ed25519" ? KEYRING_WRAP_INFO : ENC.encode(`starfish-wrap:${kemAlg}`)
}

/** A present alg tag, or `undefined` when it is the `ed25519` default (omitted on the wire). */
function tagIfPresent(alg: Alg): Alg | undefined {
  return alg === DEFAULT_ALG ? undefined : alg
}

// ── Core wrap / unwrap ────────────────────────────────────────────────────────

/**
 * Wraps a CEK for a single recipient using ephemeral ECDH under the recipient's
 * KEM suite (`opts.kemAlg`, default `ed25519`/X25519).
 *
 * Generates a fresh ephemeral keypair of that suite (or uses `opts.ephPriv` if
 * provided, useful for reproducible vectors), runs the suite ECDH with the
 * recipient's KEM pubkey, derives the wrap key via HKDF-SHA256 (info
 * domain-separated per suite), and encrypts the CEK with AES-256-GCM. The adder
 * signs the entry under `opts.addedByAlg` (default `ed25519`) for audit.
 */
export async function wrapForRecipient(
  cek: Uint8Array,
  recipientKemPubHex: string,
  opts: {
    adderEdPrivHex: string
    adderEdPubHex: string
    addedAt: number
    epoch: number
    kemAlg?: Alg
    addedByAlg?: Alg
    ephPriv?: Uint8Array
    iv?: Uint8Array
  },
): Promise<WrappedKeyEntry> {
  const kemAlg = opts.kemAlg ?? DEFAULT_ALG
  const addedByAlg = opts.addedByAlg ?? DEFAULT_ALG
  const kemSuite = getSuite(kemAlg)
  const signSuite = getSuite(addedByAlg)

  const ephPrivHex = opts.ephPriv ? bytesToHex(opts.ephPriv) : kemSuite.generateKemKeypair().privHex
  const ephKemHex = kemSuite.kemPublic(ephPrivHex)

  // deriveSharedSecret asserts a usable (non-degenerate) secret, fail closed.
  const shared = kemSuite.deriveSharedSecret(ephPrivHex, recipientKemPubHex)
  const wrapKeyBytes = await hkdfBytes(shared, KEYRING_WRAP_SALT, wrapInfo(kemAlg), 32)
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
    kemAlg: tagIfPresent(kemAlg),
    addedByAlg: tagIfPresent(addedByAlg),
  })
  const sigBytes = signSuite.sign(ENC.encode(canonical), opts.adderEdPrivHex)
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
    ...(tagIfPresent(kemAlg) !== undefined ? { kemAlg } : {}),
    ...(tagIfPresent(addedByAlg) !== undefined ? { addedByAlg } : {}),
  }
}

/**
 * Recovers the CEK from a `WrappedKeyEntry` using the recipient's KEM private key.
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
  const kemAlg = entry.kemAlg ?? DEFAULT_ALG
  // deriveSharedSecret asserts a usable secret + validates the peer point, fail closed.
  const shared = getSuite(kemAlg).deriveSharedSecret(recipientKemPrivHex, entry.ephKem)
  const wrapKeyBytes = await hkdfBytes(shared, KEYRING_WRAP_SALT, wrapInfo(kemAlg), 32)
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
  // Re-derive the canonical input from the entry's own (possibly absent) tags:
  // a stripped/swapped kemAlg or addedByAlg changes these bytes and fails here.
  const canonical = canonicalAddedSigInput({
    addedAt: entry.addedAt,
    addedBy: entry.addedBy,
    ct: entry.ct,
    ephKem: entry.ephKem,
    epoch,
    subKem: entry.subKem,
    kemAlg: entry.kemAlg,
    addedByAlg: entry.addedByAlg,
  })
  try {
    const sig = getBase64().decode(entry.addedSig)
    return getSuite(entry.addedByAlg ?? DEFAULT_ALG).verify(sig, ENC.encode(canonical), entry.addedBy)
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
  adder: { edPrivHex: string; edPubHex: string; alg?: Alg },
  recipients: { subKemHex: string; kemAlg?: Alg }[],
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
        kemAlg: r.kemAlg,
        addedByAlg: adder.alg,
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
  adder: { edPrivHex: string; edPubHex: string; alg?: Alg },
  currentCek: Uint8Array,
  recipientKemHex: string,
  addedAt: number = Math.floor(Date.now() / 1000),
  kemAlg: Alg = DEFAULT_ALG,
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
    kemAlg,
    addedByAlg: adder.alg,
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
  adder: { edPrivHex: string; edPubHex: string; alg?: Alg },
  retainedRecipients: { subKemHex: string; kemAlg?: Alg }[],
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
        kemAlg: r.kemAlg,
        addedByAlg: adder.alg,
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
  // Fail closed: `trustedAdders` is mandatory. The per-entry `addedSig` is
  // self-attesting (any key signs its own entry), so without a provenance pin a
  // hostile server could REPLACE the caller's entry with one wrapping an
  // attacker-chosen CEK to the caller's KEM pubkey and self-sign it. Requiring
  // the trusted-adder set closes that substitution by construction.
  if (!opts.trustedAdders || opts.trustedAdders.length === 0) {
    throw new Error(
      "createKeyringEncryptor: `trustedAdders` is required — pass the Ed25519 pubkey(s) " +
        "you trust to grant keyring access (e.g. the collection owner's root key). " +
        "Without it a hostile server could substitute a wrapped-key entry (the addedSig is self-attesting).",
    )
  }
  // Epoch rollback guard: the keyring has no built-in epoch floor, so a hostile
  // server could serve a STALE keyring (lower currentEpoch) to undo a rotation.
  // Reject any keyring below the caller's last-seen epoch (persisted client-side).
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
      // Duplicate entries for one recipient: the keyring was tampered with.
      // Fail closed — never pick one and risk adopting an attacker CEK.
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
