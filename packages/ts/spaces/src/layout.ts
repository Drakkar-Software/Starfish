/**
 * Default `SpaceLayout` — implements the canonical octospaces path and
 * cap-scope structure.
 *
 * This is the value used when no `layout` override is supplied via
 * {@link configureSpaces}. Any app whose server uses the standard Starfish
 * server configuration (the octospaces layout) can use this directly.
 *
 * Override individual methods or create a fresh object implementing
 * {@link SpaceLayout} to support alternative collection names, deeper
 * namespacing, or multi-tenant path schemes.
 */
import { sha256 } from "@noble/hashes/sha2.js"
import { bytesToHex, hexToBytes } from "@drakkar.software/starfish-keyring"
import type { SpaceLayout } from "./config.js"

// ── Constants ──────────────────────────────────────────────────────────────────

/**
 * Standard object-content collection names.
 *
 * These are the collections that a space member cap must cover (read / write
 * as appropriate). They mirror the octospaces server's registered collection
 * list; changing them requires a matching server-side change.
 */
export const OBJECT_COLLECTIONS = [
  "spacekeyring",
  "objindex",
  "objlog",
  "objsnap",
  "objdoc",
  "objblob",
  "typeindex",
  "objpub",
  "objpublog",
]

/** Length of a userId in hex characters (= first 16 bytes of sha256). */
export const USER_ID_HEX_LENGTH = 32

/** Length of a keyring recipient label in hex characters. */
export const RECIPIENT_LABEL_LEN = 8

// ── userId derivation ──────────────────────────────────────────────────────────

/**
 * Derive a `userId` from an Ed25519 public key.
 *
 * Algorithm: `sha256(edPubBytes)[0:16]` encoded as lowercase hex (32 chars).
 * This is the default `SpacesConfig.userIdFromEdPub` implementation.
 */
export async function defaultUserIdFromEdPub(edPubHex: string): Promise<string> {
  const edPubBytes = hexToBytes(edPubHex)
  const hash = sha256(edPubBytes)
  return bytesToHex(hash).slice(0, USER_ID_HEX_LENGTH)
}

// ── Path prefix helpers ────────────────────────────────────────────────────────

const pull = (rest: string) => `/pull/${rest}`
const push = (rest: string) => `/push/${rest}`

// ── Default layout ─────────────────────────────────────────────────────────────

/**
 * The canonical octospaces path layout.
 *
 * Path conventions:
 * - User-personal docs:   `/pull|push/user/{userId}/<doc>`
 * - Space shared docs:    `/pull|push/spaces/{spaceId}/<doc>`
 * - Per-node docs:        `/pull|push/spaces/{spaceId}/objects/{nodeId}/<doc>`
 * - Inbox shards:         `/pull|push/inbox/{userId}/{YYYY-MM}`
 * - Object directory:     `/pull/_index/objects/<shard>`
 *
 * All pull/push paths include the `/pull/` or `/push/` verb prefix so they can
 * be passed directly to `StarfishClient.pull()` / `.push()`.
 */
export const defaultSpaceLayout: SpaceLayout = {
  // ── Registry paths ─────────────────────────────────────────────────────────
  spacesPull: (userId) => pull(`user/${userId}/_spaces`),
  spacesPush: (userId) => push(`user/${userId}/_spaces`),
  spaceAccessPull: (spaceId) => pull(`spaces/${spaceId}/_access`),
  spaceAccessPush: (spaceId) => push(`spaces/${spaceId}/_access`),

  // ── Object index paths ─────────────────────────────────────────────────────
  objIndexPull: (spaceId) => pull(`spaces/${spaceId}/objects/_index`),
  objIndexPush: (spaceId) => push(`spaces/${spaceId}/objects/_index`),

  // ── Space-wide keyring paths ───────────────────────────────────────────────
  keyringName: (spaceId) => `spaces/${spaceId}`,
  keyringPull: (spaceId) => pull(`spaces/${spaceId}/_keyring`),
  keyringPush: (spaceId) => push(`spaces/${spaceId}/_keyring`),

  // ── Per-node keyring paths ─────────────────────────────────────────────────
  nodeKeyringName: (spaceId, nodeId) => `spaces/${spaceId}/objects/n/${nodeId}`,
  nodeKeyringPull: (spaceId, nodeId) => pull(`spaces/${spaceId}/objects/n/${nodeId}/_keyring`),
  nodeKeyringPush: (spaceId, nodeId) => push(`spaces/${spaceId}/objects/n/${nodeId}/_keyring`),

  // ── Inbox paths ────────────────────────────────────────────────────────────
  inboxPull: (identity, shard) =>
    shard ? pull(`inbox/${identity}/${shard}`) : pull(`inbox/${identity}/default`),
  inboxPush: (identity, shard) =>
    shard ? push(`inbox/${identity}/${shard}`) : push(`inbox/${identity}/default`),

  // ── Profile paths ─────────────────────────────────────────────────────────
  profilePull: (userId) => pull(`user/${userId}/profile`),
  profilePush: (userId) => push(`user/${userId}/profile`),

  // ── Object directory ───────────────────────────────────────────────────────
  objectDirPull: (shard) => pull(`_index/objects/${shard ?? "public"}`),

  // ── Cap scopes ─────────────────────────────────────────────────────────────

  ownerScope: () => ({
    ops: ["read", "write", "list"],
    collections: ["*"],
    paths: ["**"],
  }),

  spaceOwnerScope: (spaceId) => ({
    ops: ["read", "write", "list"],
    collections: OBJECT_COLLECTIONS,
    paths: [`spaces/${spaceId}/**`],
  }),

  spaceMemberScope: (spaceId, canWrite) => ({
    ops: canWrite ? ["read", "write", "list"] : ["read", "list"],
    collections: OBJECT_COLLECTIONS,
    paths: [`spaces/${spaceId}/**`],
  }),

  nodeMemberScope: (spaceId, nodeId, canWrite) => ({
    ops: canWrite ? ["read", "write", "list"] : ["read", "list"],
    collections: ["objinv"],
    paths: [`spaces/${spaceId}/objects/${nodeId}/**`],
  }),

  nodeStreamScope: (spaceId, nodeId, canWrite) => ({
    ops: canWrite ? ["read", "write", "list"] : ["read", "list"],
    collections: ["objinvlog"],
    paths: [`spaces/${spaceId}/objects/${nodeId}/**`],
  }),

  nodeKeyringScope: (spaceId, nodeId) => ({
    ops: ["read", "list"],
    collections: ["nodekeyring"],
    paths: [`spaces/${spaceId}/objects/${nodeId}/**`],
  }),

  accountScope: (userId) => ({
    ops: ["read", "write", "list"],
    collections: ["*"],
    paths: [`user/${userId}/**`, "spaces/**", `inbox/${userId}/**`],
  }),

  linkedDeviceScope: (userId) => ({
    ops: ["read", "write", "list"],
    collections: ["*"],
    paths: [`user/${userId}/**`, "spaces/**", `inbox/${userId}/**`],
  }),
}
