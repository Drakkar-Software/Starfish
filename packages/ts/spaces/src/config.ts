/**
 * `starfish-spaces` configuration.
 *
 * `SpaceLayout` is the seam that separates generic domain logic (registry,
 * members, nodes, invites, …) from the application's concrete storage paths
 * and cap scopes. Inject a custom layout if your server uses different
 * collection names or path conventions; the `defaultSpaceLayout` export
 * implements the canonical octospaces layout and is correct for any app built
 * on the standard Starfish server configuration.
 *
 * `SpacesConfig` carries all tunable constants — id prefixes, userId derivation,
 * inbox AAD namespace, and the KV key prefix for the local access store. The
 * defaults match the octospaces wire format, so an app that migrates from
 * `octospaces-sdk` to `starfish-spaces` without any override preserves full
 * data + server compatibility.
 */
import type { ScopePreset } from "@drakkar.software/starfish-identities"

// ── SpaceLayout interface ──────────────────────────────────────────────────────

/**
 * All path/scope producers needed by the spaces domain.
 *
 * Inject a custom layout via {@link SpacesConfig.layout} when your server uses
 * different collection names or path structures. For the standard Starfish server
 * (default octospaces configuration) use {@link defaultSpaceLayout} — it is the
 * value `configureSpaces()` installs when no `layout` is provided.
 */
export interface SpaceLayout {
  // ── Registry paths ────────────────────────────────────────────────────────
  /** Pull path for the user's own spaces registry (`user/{userId}/_spaces`). */
  spacesPull(userId: string): string
  /** Push path for the user's own spaces registry. */
  spacesPush(userId: string): string
  /** Pull path for a space's shared access record (`spaces/{spaceId}/_access`). */
  spaceAccessPull(spaceId: string): string
  /** Push path for a space's shared access record. */
  spaceAccessPush(spaceId: string): string

  // ── Object index paths ────────────────────────────────────────────────────
  /** Pull path for a space's unified object index. */
  objIndexPull(spaceId: string): string
  /** Push path for a space's unified object index. */
  objIndexPush(spaceId: string): string

  // ── Space-wide keyring paths ──────────────────────────────────────────────
  /**
   * The base collection name used as the `collectionName` arg to
   * `addCollectionRecipient`. Appending `/_keyring` gives the full storage path.
   */
  keyringName(spaceId: string): string
  /** Pull path for the space-wide keyring. */
  keyringPull(spaceId: string): string
  /** Push path for the space-wide keyring. */
  keyringPush(spaceId: string): string

  // ── Per-node keyring paths ────────────────────────────────────────────────
  /** The base collection name for a per-node keyring. */
  nodeKeyringName(spaceId: string, nodeId: string): string
  /** Pull path for a per-node keyring. */
  nodeKeyringPull(spaceId: string, nodeId: string): string
  /** Push path for a per-node keyring. */
  nodeKeyringPush(spaceId: string, nodeId: string): string

  // ── Inbox paths ───────────────────────────────────────────────────────────
  /** Pull path for an identity's inbox shard. */
  inboxPull(identity: string, shard?: string): string
  /** Push path for an identity's inbox shard (public-write append). */
  inboxPush(identity: string, shard?: string): string

  // ── Profile paths ─────────────────────────────────────────────────────────
  /** Pull path for a user's public profile. */
  profilePull(userId: string): string
  /** Push path for a user's public profile (owner-only). */
  profilePush(userId: string): string

  // ── Object directory (server-maintained projection) ───────────────────────
  /** Pull path for the global public-object directory shard. */
  objectDirPull(shard?: string): string

  // ── Cap scopes ────────────────────────────────────────────────────────────
  /** Full owner access to all spaces (all tiers). */
  ownerScope(): ScopePreset
  /** Full owner access to one specific space. */
  spaceOwnerScope(spaceId: string): ScopePreset
  /**
   * Member access to one SPACE — covers the space keyring, every node's content
   * docs, all under `spaces/{spaceId}/**`. Does NOT cover per-node invite content.
   */
  spaceMemberScope(spaceId: string, canWrite: boolean): ScopePreset
  /**
   * Narrow per-node cap for `invite+plaintext` content (single collection `objinv`).
   */
  nodeMemberScope(spaceId: string, nodeId: string, canWrite: boolean): ScopePreset
  /**
   * Narrow per-node cap for `invite+plaintext` append-log stream (`objinvlog`).
   */
  nodeStreamScope(spaceId: string, nodeId: string, canWrite: boolean): ScopePreset
  /**
   * READ-only per-node keyring cap (`nodekeyring`) for isolated E2EE nodes.
   */
  nodeKeyringScope(spaceId: string, nodeId: string): ScopePreset
  /** Personal cap: profile + space registry + device directory + all spaces + inbox. */
  accountScope(userId: string): ScopePreset
  /** Linked-device cap covering both content and account paths. */
  linkedDeviceScope(userId: string): ScopePreset
}

// ── KvAdapter ─────────────────────────────────────────────────────────────────

/** Minimal async key-value interface for the local space-access store. */
export interface KvAdapter {
  getItem(key: string): Promise<string | null>
  setItem(key: string, value: string): Promise<void>
  removeItem(key: string): Promise<void>
}

// ── SpacesConfig ──────────────────────────────────────────────────────────────

/**
 * Runtime configuration for the `starfish-spaces` module.
 *
 * All fields are optional. The defaults are compatible with the standard
 * octospaces wire format, preserving data + server compatibility for any app
 * migrating from `octospaces-sdk`.
 *
 * Install with {@link configureSpaces}; each field falls back to the listed
 * default when omitted. The active config is read lazily on first use.
 */
export interface SpacesConfig {
  /**
   * Path + scope layout. Default: `defaultSpaceLayout` (canonical octospaces
   * path structure). Override only if your server uses different collection
   * names or routing conventions.
   */
  layout?: SpaceLayout
  /**
   * Derive a `userId` hex string from an Ed25519 public key (hex).
   * Default: `sha256(edPub)[0:32]` (first 32 hex chars = 16 bytes).
   * Changing this breaks identity derivation for existing accounts.
   */
  userIdFromEdPub?: (edPubHex: string) => Promise<string>
  /**
   * Prefix for generated space ids. Default: `'sp-'`.
   * Changing this is a cosmetic choice; no data is keyed on this prefix.
   */
  spaceIdPrefix?: string
  /**
   * Prefix for generated node ids. Default: `'obj-'`.
   */
  nodeIdPrefix?: string
  /**
   * Namespace fragment embedded in inbox-seal AADs.
   * Default: `'octospaces:inbox:v1'` — must match across all peers for
   * sealed messages to be readable (changing breaks the wire format).
   */
  inboxAadNamespace?: string
  /**
   * KV key prefix for the local space-access store.
   * Default: `'octospaces.spaceaccess.'` — changing migrates the store key
   * and forgets locally-cached credentials (they are recovered from the
   * server-side `_spaces` doc on next hydrate).
   */
  kvKeyPrefix?: string
  /**
   * Async KV adapter for persisting the local space-access store across
   * page reloads / process restarts. When absent, access entries are held
   * in memory only and are lost on reload.
   */
  kvAdapter?: KvAdapter
}

// ── Domain types ──────────────────────────────────────────────────────────────
// Exported from this module so consumers import domain types from one place.

export type ID = string

/** Maps a joined space's id to its owner-issued member cap-cert JSON. */
export type CapMap = Record<string, string>

/**
 * Maps a link-access key (`spaceId` or `${spaceId}:${nodeId}`) to a sealed
 * invitation credential. The key embeds a bearer secret and is sealed to the
 * account's own KEM key before persisting in `_spaces.pubAccess`.
 */
export type PubAccessMap = Record<string, SealedBlob>

/** A mute value: `true` = indefinite; `number` = muted until that epoch-ms. */
export type MuteValue = true | number

/** Per-user mute preferences. */
export interface MutePrefs {
  nodes: Record<string, MuteValue>
  spaces: Record<string, MuteValue>
}

/** Per-user read marks — last-read timestamp per node. */
export interface ReadPrefs {
  nodes: Record<string, number>
}

/**
 * A joined or listed space. Visibility and encryption are per-node (see
 * `ObjectNode.access` / `ObjectNode.enc`); a space is a neutral container.
 */
export interface Space {
  id: ID
  name: string
  members: number
}

/** Any string an app assigns as an object's type. No builtins are defined here. */
export type ObjectType = string

/** How an object's content syncs. */
export type ObjectContentKind = "merge" | "append" | "none"

/**
 * Who may read a node's content (independent from whether it is E2EE):
 *  - `'public'`  — world-readable; anonymous users may access the content.
 *  - `'space'`   — any member of the parent space (default).
 *  - `'invite'`  — only members explicitly invited to this node.
 */
export type NodeAccess = "public" | "space" | "invite"

/**
 * One entry in a space's object index. Identity + tree position + light
 * metadata ONLY — heavy content lives in per-object content docs keyed by `id`.
 */
export interface ObjectNode {
  id: ID
  type: ObjectType
  parentId: ID | null
  order: number
  title: string
  emoji?: string
  updatedAt: number
  archived?: boolean
  contentKind?: ObjectContentKind
  /** Who may access this node's content. Absent ⇒ `'space'`. */
  access?: NodeAccess
  /**
   * True ⇒ content is E2EE under the space-wide keyring.
   * The combination `public + enc` is invalid.
   */
  enc?: boolean
  /** App-specific fields. */
  meta?: Record<string, unknown>
}

/** The object-index doc stored at `spaces/{spaceId}/objects/_index`. */
export interface ObjectsIndex {
  v: 1 | 2
  objects: ObjectNode[]
  updatedAt: number
}

// ── SealedBlob ────────────────────────────────────────────────────────────────

/**
 * A small secret sealed to a X25519 KEM key for transport in a plaintext sync
 * document. The `ct` field is `hex(iv[12] ‖ AES-256-GCM ciphertext)`.
 *
 * Wire-format: identical to `octospaces-sdk`'s `SealedBlob` (hex ct), preserved
 * for backward compatibility with existing `_spaces.pubAccess` blobs.
 * `v:1` indicates AAD context-binding was applied during sealing; opening without
 * the matching AAD fails immediately (relocation/downgrade-attack guard).
 */
export interface SealedBlob {
  entry: {
    addedBy: string
    addedAt: number
    epoch: number
    addedSig: string
    wrappedKey: string
  }
  /** hex-encoded `iv[12] ‖ AES-256-GCM ciphertext`. */
  ct: string
  /** v:1 = sealed with AAD context binding. */
  v?: 1
}

// ── Module-level config registry ──────────────────────────────────────────────

let _config: SpacesConfig = {}

/**
 * Install module-level defaults for `starfish-spaces`. Call once at app
 * startup (before using any spaces API). Unset fields retain their built-in
 * defaults (octospaces-compatible values).
 *
 * ```ts
 * import { configureSpaces } from '@drakkar.software/starfish-spaces'
 *
 * configureSpaces({
 *   kvAdapter: myAsyncStorage,   // enable cross-reload persistence
 *   // layout: myCustomLayout,   // only for non-standard server configs
 * })
 * ```
 */
export function configureSpaces(opts: SpacesConfig): void {
  _config = { ..._config, ...opts }
}

/** Read the active module-level config. Prefer accessing through a `Session`. */
export function getSpacesConfig(): SpacesConfig {
  return _config
}
