/**
 * Collection-scoped recipient management helpers.
 *
 * These wrap the low-level keyring functions in `keyring.ts` with HTTP-aware
 * I/O via `StarfishClient`. The keyring document for a collection lives at the
 * conventional path `<collection>/_keyring` and is fetched/pushed using the
 * `/pull/` and `/push/` route prefixes.
 *
 * Hash-based conflict detection is preserved: each push uses the hash from
 * the prior pull as `baseHash`. Callers may retry on `ConflictError`.
 */

import type { Alg } from "@drakkar.software/starfish-protocol"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { StarfishHttpError } from "@drakkar.software/starfish-client"
import type { Keyring, WrappedKeyEntry } from "./keyring.js"
import {
  addRecipient as keyringAddRecipient,
  rotateEpoch,
  unwrapFromEntry,
  verifyEntrySignature,
} from "./keyring.js"

/**
 * Computes the document path used to store a collection's keyring.
 * Returns `${collectionName}/_keyring`. The helpers below prefix this with
 * `/pull/` or `/push/` as required by the route layer.
 */
export function keyringPathFor(collectionName: string): string {
  return `${collectionName}/_keyring`
}

/** A recipient referenced by its KEM public key, with optional metadata. */
export interface RecipientRef {
  /** Recipient KEM pubkey (hex) of suite `kemAlg` (X25519 for ed25519). */
  subKem: string
  /** Recipient KEM suite. Absent ⇒ `ed25519` (X25519). */
  kemAlg?: Alg
  userId?: string
  label?: string
}

/** Adder's keypair material — the device must already be in the current epoch. */
export interface AdderKeys {
  edPriv: string
  edPub: string
  kemPriv: string
  /** Adder's signing suite (governs the entry's `addedSig`). Absent ⇒ `ed25519`. */
  alg?: Alg
}

/** Optional knobs shared by the recipient-mutation helpers. */
export interface RecipientMutationOpts {
  /**
   * Ed25519 pubkeys (hex) of adders the caller trusts to have written keyring
   * entries — the same pin `createKeyringEncryptor` accepts. The `addedSig`
   * audit signature is *self-attesting* (any key signs its own entry), so a
   * hostile server can REPLACE the caller's own entry with one that wraps an
   * attacker-chosen CEK to the caller's KEM pubkey (every field is derivable
   * from the caller's *public* key) and self-sign it. `recoverCurrentCek`
   * would then unwrap that forged CEK and re-wrap it for the new recipient.
   * When `trustedAdders` is set, entries whose `addedBy` is not listed are
   * ignored, closing that substitution. Strongly recommended whenever the
   * server is not fully trusted.
   */
  trustedAdders?: string[]
}

/**
 * Resolve the mandatory `trustedAdders` pin into a Set, or throw. The mutation
 * helpers recover the current CEK from a server-supplied keyring; without a
 * provenance pin a hostile server could substitute a forged entry (the
 * `addedSig` is self-attesting). Fail closed rather than mutate off unverified
 * key material.
 */
function requireTrustedAdders(trustedAdders: string[] | undefined, fn: string): Set<string> {
  if (!trustedAdders || trustedAdders.length === 0) {
    throw new Error(
      `${fn}: \`trustedAdders\` is required — pass the Ed25519 pubkey(s) you trust to grant ` +
        `keyring access (e.g. the collection owner's root key). Without it a hostile server ` +
        `could substitute a wrapped-key entry (the addedSig is self-attesting).`,
    )
  }
  return new Set(trustedAdders)
}

function pullPathFor(collectionName: string): string {
  return `/pull/${keyringPathFor(collectionName)}`
}

function pushPathFor(collectionName: string): string {
  return `/push/${keyringPathFor(collectionName)}`
}

/**
 * Pulls the current keyring document. Returns `null` if no keyring exists yet
 * (HTTP 404). Any other error propagates.
 */
async function pullKeyring(
  client: StarfishClient,
  collectionName: string,
): Promise<{ keyring: Keyring; hash: string } | null> {
  try {
    const result = await client.pull(pullPathFor(collectionName))
    return { keyring: result.data as unknown as Keyring, hash: result.hash }
  } catch (err) {
    if (err instanceof StarfishHttpError && err.status === 404) return null
    throw err
  }
}

/**
 * Locates the adder's wrapped key entry in the current epoch and recovers the
 * CEK. Throws if the adder is not a member of the current epoch.
 *
 * Each candidate entry's `addedSig` is verified before the unwrap attempt:
 * a tampered audit signature (e.g. `addedBy` or `addedAt` mutated by an
 * intermediary) causes the entry to be skipped, so the client never trusts
 * unattested wrap material. A single corrupted entry does not prevent the
 * adder from recovering the CEK via another valid entry in the same epoch.
 */
async function recoverCurrentCek(
  keyring: Keyring,
  adderKemPriv: string,
  trustedAdders?: Set<string>,
): Promise<Uint8Array> {
  const epochKey = String(keyring.currentEpoch)
  const epoch = keyring.epochs[epochKey]
  if (!epoch) {
    throw new Error(`Epoch ${keyring.currentEpoch} not found in keyring`)
  }

  // A valid epoch has unique subKems (enforced on write by addRecipient).
  // Duplicates mean the keyring was tampered with — e.g. a hostile server
  // injected an entry wrapping an attacker-chosen CEK to this adder's key.
  // Fail closed rather than risk recovering and re-wrapping a forged CEK.
  const seenSubKems = new Set<string>()
  for (const e of epoch.wrappedKeys) {
    if (seenSubKems.has(e.subKem)) {
      throw new Error(
        `Keyring epoch ${keyring.currentEpoch} has duplicate entries for subKem=${e.subKem} (tampering)`,
      )
    }
    seenSubKems.add(e.subKem)
  }

  let lastErr: unknown
  for (const entry of epoch.wrappedKeys) {
    if (trustedAdders && !trustedAdders.has(entry.addedBy)) {
      console.warn(
        `[starfish:recipients] skipping entry subKem=${entry.subKem} in epoch ${keyring.currentEpoch}: addedBy ${entry.addedBy} is not a trusted adder`,
      )
      continue
    }
    const sigOk = await verifyEntrySignature(entry, keyring.currentEpoch)
    if (!sigOk) {
      console.warn(
        `[starfish:recipients] skipping entry subKem=${entry.subKem} in epoch ${keyring.currentEpoch}: addedSig verification failed`,
      )
      continue
    }
    try {
      return await unwrapFromEntry(entry, adderKemPriv)
    } catch (err) {
      lastErr = err
    }
  }
  throw new Error(
    `Adder has no usable entry in current epoch ${keyring.currentEpoch}`,
    lastErr instanceof Error ? { cause: lastErr } : undefined,
  )
}

/**
 * Adds a new recipient to the current epoch without rotating it. Pulls the
 * current keyring, unwraps the CEK using the adder's KEM private key, appends
 * a new entry signed by the adder, and pushes the updated keyring back using
 * the prior hash as `baseHash` for conflict detection.
 *
 * Throws if the keyring document does not exist yet.
 */
export async function addRecipient(
  client: StarfishClient,
  collectionName: string,
  recipient: RecipientRef,
  adder: AdderKeys,
  opts: RecipientMutationOpts = {},
): Promise<void> {
  const pulled = await pullKeyring(client, collectionName)
  if (!pulled) {
    throw new Error(
      `Cannot add recipient: no keyring exists at ${keyringPathFor(collectionName)}. ` +
        `Create the keyring first.`,
    )
  }

  const trustedAdders = requireTrustedAdders(opts.trustedAdders, "addRecipient")
  const currentCek = await recoverCurrentCek(pulled.keyring, adder.kemPriv, trustedAdders)
  const next = await keyringAddRecipient(
    pulled.keyring,
    { edPrivHex: adder.edPriv, edPubHex: adder.edPub, alg: adder.alg },
    currentCek,
    recipient.subKem,
    undefined,
    recipient.kemAlg,
  )

  await client.push(
    pushPathFor(collectionName),
    next as unknown as Record<string, unknown>,
    pulled.hash,
  )
}

/**
 * Rotates the epoch, dropping the named recipients. Pulls the current
 * keyring, mints a fresh CEK, wraps it for every retained recipient, and
 * pushes the updated keyring using the prior hash as `baseHash`.
 *
 * Throws if the keyring document does not exist yet.
 */
export async function removeRecipient(
  client: StarfishClient,
  collectionName: string,
  removeSubKems: string[],
  adder: AdderKeys,
  opts: RecipientMutationOpts = {},
): Promise<{ newEpoch: number }> {
  const pulled = await pullKeyring(client, collectionName)
  if (!pulled) {
    throw new Error(
      `Cannot remove recipient: no keyring exists at ${keyringPathFor(collectionName)}.`,
    )
  }

  const epochKey = String(pulled.keyring.currentEpoch)
  const epoch = pulled.keyring.epochs[epochKey]
  if (!epoch) {
    throw new Error(`Epoch ${pulled.keyring.currentEpoch} not found in keyring`)
  }

  // Entries written by an untrusted adder (e.g. a recipient a hostile server
  // injected) are not carried into the new epoch — the rotation would otherwise
  // re-wrap the fresh CEK for them. `trustedAdders` is mandatory (fail closed).
  const trustedAdders = requireTrustedAdders(opts.trustedAdders, "removeRecipient")
  const removeSet = new Set(removeSubKems)
  const retainedRecipients = epoch.wrappedKeys
    .filter((e) => !removeSet.has(e.subKem))
    .filter((e) => trustedAdders.has(e.addedBy))
    .map((e) => ({ subKemHex: e.subKem, kemAlg: e.kemAlg }))

  const { keyring: rotated } = await rotateEpoch(
    pulled.keyring,
    { edPrivHex: adder.edPriv, edPubHex: adder.edPub, alg: adder.alg },
    retainedRecipients,
  )

  await client.push(
    pushPathFor(collectionName),
    rotated as unknown as Record<string, unknown>,
    pulled.hash,
  )

  return { newEpoch: rotated.currentEpoch }
}

/** One recipient projected for listing. */
export interface ListedRecipient {
  subKem: string
  addedBy: string
  addedAt: number
}

/**
 * Lists recipients in the current epoch, filtered by provenance. Returns only
 * entries whose `addedBy` is in `trustedAdders` AND whose `addedSig` verifies —
 * mirroring `createKeyringEncryptor`, so a forged or server-substituted entry
 * never surfaces in a membership/admin view.
 *
 * `trustedAdders` is REQUIRED (fail-closed): the keyring is fetched from an
 * untrusted server and the per-entry `addedSig` is self-attesting, so without a
 * provenance pin a hostile server could spoof the listing. Returns
 * `{epoch: 0, recipients: []}` if no keyring document exists yet.
 */
export async function listRecipients(
  client: StarfishClient,
  collectionName: string,
  opts: { trustedAdders?: string[] } = {},
): Promise<{ epoch: number; recipients: ListedRecipient[] }> {
  const trusted = requireTrustedAdders(opts.trustedAdders, "listRecipients")
  const pulled = await pullKeyring(client, collectionName)
  if (!pulled) return { epoch: 0, recipients: [] }

  const epoch = pulled.keyring.epochs[String(pulled.keyring.currentEpoch)]
  if (!epoch) {
    return { epoch: pulled.keyring.currentEpoch, recipients: [] }
  }

  const recipients: ListedRecipient[] = []
  for (const e of epoch.wrappedKeys as WrappedKeyEntry[]) {
    if (!trusted.has(e.addedBy)) continue
    if (!(await verifyEntrySignature(e, pulled.keyring.currentEpoch))) continue
    recipients.push({ subKem: e.subKem, addedBy: e.addedBy, addedAt: e.addedAt })
  }
  return { epoch: pulled.keyring.currentEpoch, recipients }
}

/**
 * Returns the current epoch number of the keyring document. Returns 0 if no
 * keyring exists yet.
 */
export async function currentEpoch(
  client: StarfishClient,
  collectionName: string,
): Promise<number> {
  const pulled = await pullKeyring(client, collectionName)
  if (!pulled) return 0
  return pulled.keyring.currentEpoch
}
