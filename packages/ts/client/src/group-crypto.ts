/**
 * Group encryption utilities for Starfish.
 *
 * Enables multiple users to share a common encrypted collection without sharing
 * a passphrase. Each member holds their own credentials; a Group Encryption Key
 * (GEK) is distributed per-member using X25519 ECDH key agreement.
 *
 * Typical flow:
 *   1. Each user calls `deriveCredentials(passphrase)` — now includes groupPublicKey / groupPrivateKey.
 *   2. Admin calls `createGroupKeyring(...)` to create a keyring document.
 *   3. Members call `createGroupEncryptor(keyringData, myIdentity, myPrivateKey)` to get an Encryptor.
 *   4. The Encryptor is passed to SyncManager via the `encryptor` option.
 */

import { x25519 } from "@noble/curves/ed25519.js"
import { getCrypto, getBase64, IV_BYTES, deriveKey } from "@drakkar.software/starfish-protocol"
import type { Encryptor } from "./crypto.js"
import { createEncryptor } from "./crypto.js"

// ── Internal helpers ──────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

const ALGO = "AES-GCM"
const GROUP_WRAP_SALT = "starfish-group-wrap"
const GROUP_WRAP_INFO = "starfish-group-wrap"
const GROUP_ECDH_DOMAIN = "starfish-group-ecdh"
const GROUP_DATA_INFO = "starfish-group"
const GEK_BYTES = 32

// ── Types ─────────────────────────────────────────────────────────────────────

/** An ECDH key pair used for group encryption. Hex-encoded for easy serialization. */
export interface GroupKeyPair {
  /** Hex-encoded X25519 private key (32 bytes). Keep secret — never store on server. */
  privateKey: string
  /** Hex-encoded X25519 public key (32 bytes). Safe to publish. */
  publicKey: string
}

/** One epoch's wrapped keys: each member's GEK encrypted to their public key. */
export interface EpochKeyring {
  /** The admin's hex-encoded X25519 public key (used for ECDH by members). */
  adminPublicKey: string
  /** Map from member identity (userId) → base64(IV || AES-GCM(GEK)) */
  wrappedKeys: Record<string, string>
}

/** The full keyring document stored in a Starfish collection. Push this with any SyncManager. */
export interface GroupKeyring {
  /** The epoch number currently used for new encryptions. */
  currentEpoch: number
  /** All epochs. Members unwrap the GEK for whichever epoch a document was encrypted with. */
  epochs: Record<string, EpochKeyring>
}

// ── Key derivation ────────────────────────────────────────────────────────────

/**
 * Derives a deterministic X25519 key pair from a passphrase + userId.
 *
 * The derivation uses SHA-256 with a fixed domain separator so it is distinct
 * from the auth token and encryption key derivations. Same passphrase + userId
 * always produces the same key pair on any device (stateless).
 */
export async function deriveGroupKeyPair(passphrase: string, userId: string): Promise<GroupKeyPair> {
  const c = getCrypto()
  const enc = new TextEncoder()
  const input = enc.encode(`${passphrase}:${userId}:${GROUP_ECDH_DOMAIN}`)
  const hash = await c.subtle.digest("SHA-256", input)
  const privateKeyBytes = new Uint8Array(hash)
  const publicKeyBytes = x25519.getPublicKey(privateKeyBytes)
  return { privateKey: bytesToHex(privateKeyBytes), publicKey: bytesToHex(publicKeyBytes) }
}

// ── GEK generation ────────────────────────────────────────────────────────────

/** Generates a random 256-bit Group Encryption Key as a hex string. */
export function generateGroupKey(): string {
  const c = getCrypto()
  return bytesToHex(c.getRandomValues(new Uint8Array(GEK_BYTES)))
}

// ── Key wrapping / unwrapping ─────────────────────────────────────────────────

/**
 * Wraps a GEK for a specific member using ECDH key agreement.
 *
 * The wrapper (admin) and member each have an X25519 key pair. ECDH between
 * `wrapperPrivateKey` and `memberPublicKey` produces a shared secret, which is
 * used to derive an AES-256-GCM key that encrypts the GEK.
 *
 * @returns base64(IV || AES-GCM-ciphertext)
 */
export async function wrapGroupKey(
  gek: string,
  memberPublicKey: string,
  wrapperPrivateKey: string,
): Promise<string> {
  const sharedSecret = x25519.getSharedSecret(hexToBytes(wrapperPrivateKey), hexToBytes(memberPublicKey))
  const wrappingKey = await deriveKey(bytesToHex(sharedSecret), GROUP_WRAP_SALT, GROUP_WRAP_INFO)

  const c = getCrypto()
  const b64 = getBase64()
  const iv = c.getRandomValues(new Uint8Array(IV_BYTES))
  const encrypted = await c.subtle.encrypt({ name: ALGO, iv }, wrappingKey, hexToBytes(gek))

  const combined = new Uint8Array(IV_BYTES + encrypted.byteLength)
  combined.set(iv)
  combined.set(new Uint8Array(encrypted), IV_BYTES)
  return b64.encode(combined)
}

/**
 * Unwraps a GEK using the member's own private key and the admin's public key.
 *
 * ECDH between `memberPrivateKey` and `adminPublicKey` yields the same shared
 * secret as the wrapping step, so the same AES key is derived and the GEK is
 * recovered.
 *
 * @returns GEK as a hex string
 */
export async function unwrapGroupKey(
  wrapped: string,
  memberPrivateKey: string,
  adminPublicKey: string,
): Promise<string> {
  const sharedSecret = x25519.getSharedSecret(hexToBytes(memberPrivateKey), hexToBytes(adminPublicKey))
  const wrappingKey = await deriveKey(bytesToHex(sharedSecret), GROUP_WRAP_SALT, GROUP_WRAP_INFO)

  const b64 = getBase64()
  const c = getCrypto()
  const combined = b64.decode(wrapped)
  const iv = combined.slice(0, IV_BYTES)
  const ciphertext = combined.slice(IV_BYTES)
  const decrypted = await c.subtle.decrypt({ name: ALGO, iv }, wrappingKey, ciphertext)
  return bytesToHex(new Uint8Array(decrypted))
}

// ── Keyring management ────────────────────────────────────────────────────────

/**
 * Creates a new group keyring document with epoch 1.
 *
 * @param adminKeyPair  The admin's key pair (from `deriveGroupKeyPair` or `deriveCredentials`)
 * @param members       Map from member identity (userId) → hex public key
 * @param gek           Optional GEK to use; generated randomly if omitted
 * @returns             The keyring document and the raw GEK (admin keeps the GEK to add future members)
 */
export async function createGroupKeyring(
  adminKeyPair: GroupKeyPair,
  members: Record<string, string>,
  gek?: string,
): Promise<{ keyring: GroupKeyring; gek: string }> {
  const resolvedGek = gek ?? generateGroupKey()
  const wrappedKeys: Record<string, string> = {}
  for (const [memberId, memberPublicKey] of Object.entries(members)) {
    wrappedKeys[memberId] = await wrapGroupKey(resolvedGek, memberPublicKey, adminKeyPair.privateKey)
  }
  const keyring: GroupKeyring = {
    currentEpoch: 1,
    epochs: {
      "1": { adminPublicKey: adminKeyPair.publicKey, wrappedKeys },
    },
  }
  return { keyring, gek: resolvedGek }
}

/**
 * Adds a new member to the current epoch of an existing keyring.
 *
 * The admin supplies the current GEK (returned by `createGroupKeyring` or
 * `rotateGroupKey`) and their key pair to wrap it for the new member.
 * This does NOT rotate the GEK — the new member can read all existing
 * documents encrypted with the current epoch key.
 *
 * Only the admin (whose `publicKey` matches `epochKeyring.adminPublicKey`) can
 * add members, because all wrapped entries must use the same ECDH key pair.
 */
export async function addGroupMember(
  keyring: GroupKeyring,
  adminKeyPair: GroupKeyPair,
  currentGek: string,
  newMemberId: string,
  newMemberPublicKey: string,
): Promise<GroupKeyring> {
  const epochKey = String(keyring.currentEpoch)
  const epochKeyring = keyring.epochs[epochKey]
  if (!epochKeyring) throw new Error(`Epoch ${keyring.currentEpoch} not found in keyring`)
  if (epochKeyring.adminPublicKey !== adminKeyPair.publicKey) {
    throw new Error(`Provided key pair does not match the admin public key stored in epoch ${keyring.currentEpoch}`)
  }

  const wrapped = await wrapGroupKey(currentGek, newMemberPublicKey, adminKeyPair.privateKey)

  return {
    ...keyring,
    epochs: {
      ...keyring.epochs,
      [epochKey]: {
        ...epochKeyring,
        wrappedKeys: { ...epochKeyring.wrappedKeys, [newMemberId]: wrapped },
      },
    },
  }
}

/**
 * Rotates the group key, creating a new epoch.
 *
 * Used when removing a member. The removed member retains their old epoch key
 * (and can still read old documents), but cannot read new documents.
 *
 * @param remainingMembers  Map from identity → hex public key for members who keep access
 */
export async function rotateGroupKey(
  keyring: GroupKeyring,
  adminKeyPair: GroupKeyPair,
  remainingMembers: Record<string, string>,
  newGek?: string,
): Promise<{ keyring: GroupKeyring; gek: string }> {
  const resolvedGek = newGek ?? generateGroupKey()
  const newEpoch = keyring.currentEpoch + 1
  const wrappedKeys: Record<string, string> = {}
  for (const [memberId, memberPublicKey] of Object.entries(remainingMembers)) {
    wrappedKeys[memberId] = await wrapGroupKey(resolvedGek, memberPublicKey, adminKeyPair.privateKey)
  }
  const newKeyring: GroupKeyring = {
    currentEpoch: newEpoch,
    epochs: {
      ...keyring.epochs,
      [String(newEpoch)]: { adminPublicKey: adminKeyPair.publicKey, wrappedKeys },
    },
  }
  return { keyring: newKeyring, gek: resolvedGek }
}

// ── Encryptor factory ─────────────────────────────────────────────────────────

/**
 * Creates an Encryptor that can decrypt any epoch and encrypts with the current epoch.
 *
 * Wire format: `{ _encrypted: "base64(IV || ciphertext)", _epoch: N }`
 *
 * @param keyring         The keyring document fetched from Starfish
 * @param myIdentity      The caller's userId (to locate their wrapped key in each epoch)
 * @param myPrivateKey    The caller's hex-encoded X25519 private key
 */
export async function createGroupEncryptor(
  keyring: GroupKeyring,
  myIdentity: string,
  myPrivateKey: string,
): Promise<Encryptor> {
  // Unwrap GEK for each epoch we have a key for
  const epochEncryptors = new Map<number, Encryptor>()
  for (const [epochStr, epochKeyring] of Object.entries(keyring.epochs)) {
    const epoch = parseInt(epochStr, 10)
    const wrapped = epochKeyring.wrappedKeys[myIdentity]
    if (!wrapped) continue
    const gek = await unwrapGroupKey(wrapped, myPrivateKey, epochKeyring.adminPublicKey)
    epochEncryptors.set(epoch, createEncryptor(gek, `epoch-${epoch}`, GROUP_DATA_INFO))
  }

  const currentEpoch = keyring.currentEpoch
  const currentEncryptor = epochEncryptors.get(currentEpoch)
  if (!currentEncryptor) {
    throw new Error(
      `No wrapped key found for identity "${myIdentity}" in epoch ${currentEpoch}. ` +
        `Ensure the admin has added this member to the keyring.`,
    )
  }

  return {
    async encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>> {
      const encrypted = await currentEncryptor.encrypt(data)
      return { ...encrypted, _epoch: currentEpoch }
    },

    async decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>> {
      const epoch = typeof wrapper._epoch === "number" ? wrapper._epoch : currentEpoch
      const encryptor = epochEncryptors.get(epoch)
      if (!encryptor) {
        throw new Error(
          `No key available for epoch ${epoch}. ` +
            `This document was encrypted in a different epoch. ` +
            `Ensure your keyring is up to date.`,
        )
      }
      return encryptor.decrypt(wrapper)
    },
  }
}
