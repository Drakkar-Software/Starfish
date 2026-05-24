/**
 * Device directory helpers — owner-side audit/UI metadata for the per-user
 * device list at `users/{rootUserId}/_devices`.
 *
 * One entry per `kind: "device"` cap the root has issued. The doc is reachable
 * by any of the root's devices because their caps inherently include the
 * `users/{identity}/_devices` path through the standard `rootAll` scope.
 *
 * The directory is **not** an authority source. Auth flows entirely through the
 * cap-cert presented in `Authorization` headers and the
 * `_revocations/{rootUserId}` document. This module exists for UI ("your
 * linked devices") and for revoke-by-sub lookup when callers don't want to
 * remember nonces out-of-band.
 *
 * Member directory helpers (`addMemberEntry`, `listMembers`,
 * `removeMemberEntry`, `membersPathFor`) live in
 * `@drakkar.software/starfish-sharing`.
 */

import type { CapCert } from "@drakkar.software/starfish-protocol"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ConflictError, StarfishHttpError } from "@drakkar.software/starfish-client"

// ── Types & paths ────────────────────────────────────────────────────────────

/** A single entry in a device or member directory document. */
export interface DirectoryEntry {
  /** Base64 cap nonce — identifies the cert. */
  nonce: string
  /** Subject Ed25519 pubkey, hex (32 B). */
  sub: string
  /** Subject X25519 pubkey, hex (32 B). */
  subKem: string
  /** `sha256(sub)[0:32]`. Required for member caps; undefined for device caps. */
  subUserId?: string
  /** Cap's `scope` block, mirrored verbatim. */
  scope: CapCert["scope"]
  /** Cap's not-before (unix seconds). */
  nbf: number
  /** Cap's expiry (unix seconds). */
  exp: number
  /** Optional human-readable label, e.g. "Alice's iPhone". */
  label?: string
  /** Ed25519 pubkey of the device that wrote this entry, hex (optional). */
  addedBy?: string
  /** Unix seconds when the entry was added. */
  addedAt: number
}

/** Directory document stored at the conventional path. */
export interface Directory {
  v: 1
  entries: DirectoryEntry[]
}

/** Directory entry for a `kind: "device"` cap. */
export type DeviceEntry = DirectoryEntry

/** Returns the storage path for a root's devices directory. */
export function devicesPathFor(rootUserId: string): string {
  return `users/${rootUserId}/_devices`
}

// ── HTTP helpers (shared with sharing.directory but intentionally duplicated) ─

async function pullDirectory(
  client: StarfishClient,
  path: string,
): Promise<{ directory: Directory; hash: string | null }> {
  try {
    const result = await client.pull(`/pull/${path}`)
    return {
      directory: result.data as unknown as Directory,
      hash: result.hash,
    }
  } catch (err) {
    if (err instanceof StarfishHttpError && err.status === 404) {
      return { directory: { v: 1, entries: [] }, hash: null }
    }
    throw err
  }
}

function entryFromCert(
  cert: CapCert,
  label?: string,
  addedBy?: string,
): DirectoryEntry {
  // This directory records single-subject device caps; a subject-less cap
  // (e.g. an audience cap) has no place here.
  if (cert.sub === undefined || cert.subKem === undefined) {
    throw new Error("cannot record a subject-less cap (e.g. audience) in the device directory")
  }
  const entry: DirectoryEntry = {
    nonce: cert.nonce,
    sub: cert.sub,
    subKem: cert.subKem,
    scope: cert.scope,
    nbf: cert.nbf,
    exp: cert.exp,
    addedAt: Math.floor(Date.now() / 1000),
  }
  if (cert.subUserId !== undefined) entry.subUserId = cert.subUserId
  if (label !== undefined) entry.label = label
  if (addedBy !== undefined) entry.addedBy = addedBy
  return entry
}

const MAX_RETRIES = 3

export async function upsertEntry(
  client: StarfishClient,
  path: string,
  cert: CapCert,
  opts: { label?: string; addedBy?: string },
): Promise<void> {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const { directory, hash } = await pullDirectory(client, path)
    const filtered = directory.entries.filter((e) => e.nonce !== cert.nonce)
    const next: Directory = {
      v: 1,
      entries: [...filtered, entryFromCert(cert, opts.label, opts.addedBy)],
    }
    try {
      await client.push(
        `/push/${path}`,
        next as unknown as Record<string, unknown>,
        hash,
      )
      return
    } catch (err) {
      if (err instanceof ConflictError && attempt < MAX_RETRIES - 1) {
        continue
      }
      throw err
    }
  }
  throw new Error(`directory.upsertEntry: too many baseHash conflicts at ${path}`)
}

export async function removeEntryByNonce(
  client: StarfishClient,
  path: string,
  nonce: string,
): Promise<boolean> {
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const { directory, hash } = await pullDirectory(client, path)
    if (!directory.entries.some((e) => e.nonce === nonce)) return false
    const next: Directory = {
      v: 1,
      entries: directory.entries.filter((e) => e.nonce !== nonce),
    }
    try {
      await client.push(
        `/push/${path}`,
        next as unknown as Record<string, unknown>,
        hash,
      )
      return true
    } catch (err) {
      if (err instanceof ConflictError && attempt < MAX_RETRIES - 1) {
        continue
      }
      throw err
    }
  }
  throw new Error(`directory.removeEntryByNonce: too many baseHash conflicts at ${path}`)
}

/** Optional filters applied at list time. */
export interface ListDirectoryOpts {
  /** When true, expired entries are returned too (default: false). */
  includeExpired?: boolean
  /** When set, entries whose nonce appears here are filtered out. */
  revokedNonces?: ReadonlySet<string>
}

export async function listEntries(
  client: StarfishClient,
  path: string,
  opts: ListDirectoryOpts,
): Promise<DirectoryEntry[]> {
  const { directory } = await pullDirectory(client, path)
  const now = Math.floor(Date.now() / 1000)
  return directory.entries.filter((e) => {
    if (!opts.includeExpired && e.exp < now) return false
    if (opts.revokedNonces?.has(e.nonce)) return false
    return true
  })
}

// ── Devices ──────────────────────────────────────────────────────────────────

/**
 * Append (or overwrite by nonce) a device cap-cert entry in the directory at
 * `users/{rootUserId}/_devices`. Pull-merge-push with baseHash retry.
 *
 * Throws when `cert.kind !== "device"`.
 */
export async function addDeviceEntry(
  client: StarfishClient,
  rootUserId: string,
  cert: CapCert,
  opts: { label?: string; addedBy?: string } = {},
): Promise<void> {
  if (cert.kind !== "device") {
    throw new Error(
      `addDeviceEntry: expected kind="device", got kind="${cert.kind}"`,
    )
  }
  await upsertEntry(client, devicesPathFor(rootUserId), cert, opts)
}

/**
 * List devices recorded in the directory for `rootUserId`. Returns the empty
 * list when no directory document exists yet.
 *
 * By default, expired entries are filtered out; pass `includeExpired: true`
 * to keep them. Pass `revokedNonces` (typically built by reading
 * `_revocations/{rootUserId}` separately) to also drop revoked entries.
 */
export async function listDevices(
  client: StarfishClient,
  rootUserId: string,
  opts: ListDirectoryOpts = {},
): Promise<DeviceEntry[]> {
  return listEntries(client, devicesPathFor(rootUserId), opts)
}

/**
 * Remove a device entry by nonce. Returns `true` when the entry existed and
 * was removed, `false` when no matching entry was present.
 *
 * Note: removing from the directory does **not** revoke the cap-cert on the
 * server. Cryptographic revocation requires appending the (sub, nonce, exp)
 * tuple to a signed `RevocationList` (build it with `buildRevocationList` from
 * `@drakkar.software/starfish-protocol`) and submitting it. Callers typically do
 * both in sequence: submit the revocation list, then call this. (For members, see
 * `evictMember` in `@drakkar.software/starfish-sharing`, which composes both.)
 */
export async function removeDeviceEntry(
  client: StarfishClient,
  rootUserId: string,
  nonce: string,
): Promise<boolean> {
  return removeEntryByNonce(client, devicesPathFor(rootUserId), nonce)
}
