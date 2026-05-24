/**
 * Member directory helpers — owner-side audit/UI metadata for
 * `<collectionPath>/_members`.
 *
 * One entry per `kind: "member"` cap the owner has issued for a given
 * collection. The doc is **owner-only**: non-admin member caps are rejected at
 * well-formedness time when they would reach `<col>/_members` (see the
 * `member-members-not-denied` rule).
 *
 * The directory is **not** an authority source. Auth flows entirely through the
 * cap-cert presented in `Authorization` headers and the
 * `_revocations/{rootUserId}` document.
 *
 * Device directory helpers (`addDeviceEntry`, `listDevices`, …) live in
 * `@drakkar.software/starfish-identities`.
 */

import type { Alg, CapCert } from "@drakkar.software/starfish-protocol"
import { recipientKem } from "@drakkar.software/starfish-protocol"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ConflictError, StarfishHttpError } from "@drakkar.software/starfish-client"

// ── Types & paths ────────────────────────────────────────────────────────────

/** A single entry in a device or member directory document. */
export interface DirectoryEntry {
  /** Base64 cap nonce — identifies the cert. */
  nonce: string
  /** Subject signing pubkey, hex (32 B), of suite `subAlg`. */
  sub: string
  /** Subject KEM pubkey, hex (32 B), of suite `subKemAlg` — the keyring recipient key. */
  subKem: string
  /** Subject KEM suite. Absent ⇒ `ed25519` (X25519). */
  subKemAlg?: Alg
  /** `sha256(sub)[0:32]`. Required for member caps; undefined for device caps. */
  subUserId?: string
  /** Cap's `scope` block, mirrored verbatim. */
  scope: CapCert["scope"]
  /** Cap's not-before (unix seconds). */
  nbf: number
  /** Cap's expiry (unix seconds). */
  exp: number
  /** Optional human-readable label, e.g. "Bob (designer)". */
  label?: string
  /** Ed25519 pubkey of the device that wrote this entry, hex (optional). */
  addedBy?: string
  /** Unix seconds when the entry was added. */
  addedAt: number
  /**
   * The full signed cap-cert. Present so a `_members` roster can double as a
   * cap-distribution list for plaintext (cap-only) collections: the owner
   * publishes each member's signed cap here and members fetch their own with
   * {@link fetchMyMemberCap}.
   * The other fields above are a redundant projection kept for back-compat and
   * for cheap `exp`/`subUserId` filtering. Safe to publish — a cap is usable
   * only by the holder of its subject (`sub`) private key (the server verifies
   * each request's signature against `cert.sub`), so a readable roster of caps
   * never lets one member act as another.
   */
  cert?: CapCert
}

/** Directory document stored at the conventional path. */
export interface Directory {
  v: 1
  entries: DirectoryEntry[]
}

/** Directory entry for a `kind: "member"` cap. */
export type MemberEntry = DirectoryEntry

/** Returns the storage path for a collection's members directory. */
export function membersPathFor(collectionPath: string): string {
  return `${collectionPath}/_members`
}

// ── HTTP helpers (intentionally duplicated from identities.directory) ────────

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
  // The `_members` directory records single-subject grants. `recipientKem`
  // resolves the recipient's KEM pubkey + suite (the dedicated `subKem` for
  // ed25519/mixed pairs, or the signing `sub` for same-suite secp256k1); it
  // throws for an audience cap, which is distributed as a public link, not a
  // roster entry.
  if (cert.sub === undefined) {
    throw new Error("cannot publish a subject-less cap (e.g. audience) to the member directory")
  }
  const { kemPubHex, kemAlg } = recipientKem(cert)
  const entry: DirectoryEntry = {
    nonce: cert.nonce,
    sub: cert.sub,
    subKem: kemPubHex,
    scope: cert.scope,
    nbf: cert.nbf,
    exp: cert.exp,
    addedAt: Math.floor(Date.now() / 1000),
    cert,
    ...(kemAlg !== "ed25519" ? { subKemAlg: kemAlg } : {}),
  }
  if (cert.subUserId !== undefined) entry.subUserId = cert.subUserId
  if (label !== undefined) entry.label = label
  if (addedBy !== undefined) entry.addedBy = addedBy
  return entry
}

const MAX_RETRIES = 3

async function upsertEntry(
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

async function removeEntryByNonce(
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

async function listEntries(
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

// ── Members ──────────────────────────────────────────────────────────────────

/**
 * Append (or overwrite by nonce) a member cap-cert entry in the directory at
 * `<collectionPath>/_members`. Pull-merge-push with baseHash retry.
 *
 * `collectionPath` is the storage prefix used by the collection — for a
 * collection whose data lives at `notes/<doc>`, pass `"notes"`. For a
 * per-owner collection at `users/<owner>/notes/<doc>`, pass
 * `"users/<owner>/notes"`.
 *
 * Throws when `cert.kind !== "member"`. The path is only writable by admin
 * or root-device caps; member caps are denied this path by the
 * `member-members-not-denied` well-formedness rule.
 */
export async function addMemberEntry(
  client: StarfishClient,
  collectionPath: string,
  cert: CapCert,
  opts: { label?: string; addedBy?: string } = {},
): Promise<void> {
  if (cert.kind !== "member") {
    throw new Error(
      `addMemberEntry: expected kind="member", got kind="${cert.kind}"`,
    )
  }
  await upsertEntry(client, membersPathFor(collectionPath), cert, opts)
}

/**
 * List members recorded for `collectionPath`. Owner-only by virtue of cap
 * scope — invoking this with a member cap returns 403 at the server. Returns
 * the empty list when no directory document exists yet.
 */
export async function listMembers(
  client: StarfishClient,
  collectionPath: string,
  opts: ListDirectoryOpts = {},
): Promise<MemberEntry[]> {
  return listEntries(client, membersPathFor(collectionPath), opts)
}

/**
 * Remove a member entry by nonce. Same caveat as device removal: this only
 * updates the directory; the server accepts the cap until it's added to the
 * revocation list and its TTL fires.
 */
export async function removeMemberEntry(
  client: StarfishClient,
  collectionPath: string,
  nonce: string,
): Promise<boolean> {
  return removeEntryByNonce(client, membersPathFor(collectionPath), nonce)
}

// ── Published caps ───────────────────────────────────────────────────────────
//
// In the plaintext, cap-only sharing mode there is no keyring. Instead the owner
// PUBLISHES each member's full signed cap into the single `<col>/_members` list
// (configure that collection read-open + owner-only write). A member fetches its
// own cap from there — no out-of-band forwarding — and presents it for content.
// This is safe even when the list is world-readable: a cap is bound to its
// subject key (the server verifies each request against `cert.sub`), so reading
// another member's cap is useless without their private key.

/**
 * Publish a member's full signed cap into `<collectionPath>/_members`. Thin,
 * intention-revealing alias for {@link addMemberEntry} (which already stores the
 * full `cert`). Owner-only by collection write-roles. Throws on a non-member cap.
 */
export async function publishMemberCap(
  client: StarfishClient,
  collectionPath: string,
  cert: CapCert,
  opts: { label?: string; addedBy?: string } = {},
): Promise<void> {
  await addMemberEntry(client, collectionPath, cert, opts)
}

/**
 * Fetch every published member cap from `<collectionPath>/_members`. Returns the
 * usable signed `CapCert`s (skipping legacy entries written before caps were
 * stored). Honors {@link ListDirectoryOpts} (`includeExpired`, `revokedNonces`).
 */
export async function fetchMemberCaps(
  client: StarfishClient,
  collectionPath: string,
  opts: ListDirectoryOpts = {},
): Promise<CapCert[]> {
  const entries = await listEntries(client, membersPathFor(collectionPath), opts)
  return entries
    .map((e) => e.cert)
    .filter((c): c is CapCert => c !== undefined)
}

/**
 * Fetch the caller's own published cap — the one whose `sub` equals their
 * Ed25519 pubkey (hex). Returns `null` when no usable cap is published for them.
 */
export async function fetchMyMemberCap(
  client: StarfishClient,
  collectionPath: string,
  myEdPubHex: string,
  opts: ListDirectoryOpts = {},
): Promise<CapCert | null> {
  const caps = await fetchMemberCaps(client, collectionPath, opts)
  return caps.find((c) => c.sub === myEdPubHex) ?? null
}

/**
 * Remove a published cap by nonce (e.g. on eviction). Alias for
 * {@link removeMemberEntry}. Returns `false` when the nonce was not present.
 */
export async function unpublishMemberCap(
  client: StarfishClient,
  collectionPath: string,
  nonce: string,
): Promise<boolean> {
  return removeMemberEntry(client, collectionPath, nonce)
}
