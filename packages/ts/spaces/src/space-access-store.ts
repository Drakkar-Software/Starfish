/**
 * Unified local access store for spaces this identity has joined.
 *
 * Two entry kinds:
 *  - `member`: a member cap-cert JSON string (safe to store in the clear).
 *    Used for PRIVATE space keyring opens.
 *  - `link`: an ephemeral-subject cap + the link's Ed25519 private key.
 *    Embeds a bearer secret so it is SEALED in the synced `_spaces.pubAccess`
 *    field before leaving this device; the local KV stores it in the clear
 *    only on the owning device.
 *
 * Two tiers: device-local KV (fast, offline) and the user's synced `_spaces`
 * doc (durable source of truth — merged OVER the local KV on hydrate).
 * Keyed PER-USER so multiple accounts on one device don't see each other's entries.
 *
 * The KV key prefix defaults to `'starfish.spaceaccess.'` (config field `kvKeyPrefix`).
 */
import type { CapMap, KvAdapter } from "./config.js"

// ── Types ──────────────────────────────────────────────────────────────────────

/** Link-based access credential: the ephemeral cap + keys a link bearer keeps. */
export interface LinkAccessPayload {
  cap: unknown
  key: string
  /**
   * Ephemeral X25519 KEM private key (hex) used to decrypt the space keyring.
   * Present in tokens from `createSpaceInviteLink` >= 0.8.6.
   * Absent in legacy tokens — fall back to `session.keys` when missing.
   */
  kemPriv?: string
  /** Ephemeral X25519 KEM public key (hex) — the keyring recipient identifier. */
  kemPub?: string
  write: boolean
}

export type SpaceAccessEntry =
  | { kind: "member"; cap: string }
  | ({ kind: "link" } & LinkAccessPayload)

export type SpaceAccessMap = Record<string, SpaceAccessEntry>

// ── Module-level state ─────────────────────────────────────────────────────────

let _cache: SpaceAccessMap = {}
let _activeKey: string | null = null
let _kv: KvAdapter | undefined = undefined
let _kvKeyPrefix = "starfish.spaceaccess."

/** Configure the KV adapter + key prefix (call once at startup). */
export function configureSpaceAccessStore(opts: {
  kvAdapter?: KvAdapter
  kvKeyPrefix?: string
}): void {
  _kv = opts.kvAdapter
  if (opts.kvKeyPrefix) _kvKeyPrefix = opts.kvKeyPrefix
}

const keyFor = (userId: string) => `${_kvKeyPrefix}${userId}`

// ── Hydration ─────────────────────────────────────────────────────────────────

/**
 * Load the active account's access entries into memory.
 *
 * Call (and await) on sign-in + account switch + after any server-side change
 * that adds new caps (e.g. after accepting an invite).
 *
 * `serverCaps` (member caps from `_spaces.caps`) and `serverLinkAccess`
 * (already-unsealed link payloads from `_spaces.pubAccess`) are merged OVER
 * the local KV cache (server wins).
 */
export async function hydrateSpaceAccessStore(
  userId: string,
  serverCaps: CapMap,
  serverLinkAccess: Record<string, LinkAccessPayload>,
  kvAdapter?: KvAdapter,
): Promise<void> {
  const kv = kvAdapter ?? _kv
  const key = keyFor(userId)
  const firstLoad = _activeKey !== key
  if (firstLoad) {
    _activeKey = key
    _cache = {}
    if (kv) {
      const raw = await kv.getItem(key)
      if (raw) {
        try {
          _cache = JSON.parse(raw) as SpaceAccessMap
        } catch (e) {
          console.error("[starfish-spaces] space-access-store: corrupt cache, resetting:", e)
          _cache = {}
        }
      }
    }
  }
  let changed = false
  for (const [spaceId, capJson] of Object.entries(serverCaps)) {
    _cache[spaceId] = { kind: "member", cap: capJson }
    changed = true
  }
  for (const [spaceId, access] of Object.entries(serverLinkAccess)) {
    _cache[spaceId] = {
      kind: "link",
      cap: access.cap,
      key: access.key,
      kemPriv: access.kemPriv,
      kemPub: access.kemPub,
      write: access.write,
    }
    changed = true
  }
  if (changed && kv && _activeKey) {
    await kv.setItem(_activeKey, JSON.stringify(_cache))
  }
}

function persist(kv?: KvAdapter): void {
  const kvToUse = kv ?? _kv
  if (_activeKey && kvToUse) void kvToUse.setItem(_activeKey, JSON.stringify(_cache)).catch(() => {})
}

// ── Space-level accessors ──────────────────────────────────────────────────────

export function getSpaceAccessEntry(spaceId: string): SpaceAccessEntry | null {
  return _cache[spaceId] ?? null
}

export function saveSpaceAccessEntry(spaceId: string, entry: SpaceAccessEntry, kv?: KvAdapter): void {
  _cache = { ..._cache, [spaceId]: entry }
  persist(kv)
}

/** Forget one space's access entry (on leaving the space). */
export function removeSpaceAccessEntry(spaceId: string, kv?: KvAdapter): void {
  if (!(spaceId in _cache)) return
  const next = { ..._cache }
  delete next[spaceId]
  _cache = next
  persist(kv)
}

// ── Per-node accessors (keyed by `${spaceId}:${nodeId}` + tier suffix) ─────────

const nodeKey = (spaceId: string, nodeId: string, suffix: "" | ":stream" | ":keyring" = "") =>
  `${spaceId}:${nodeId}${suffix}`

const nodeEntryApi = (suffix: "" | ":stream" | ":keyring") => ({
  get: (spaceId: string, nodeId: string): SpaceAccessEntry | null =>
    getSpaceAccessEntry(nodeKey(spaceId, nodeId, suffix)),
  save: (spaceId: string, nodeId: string, entry: SpaceAccessEntry): void =>
    saveSpaceAccessEntry(nodeKey(spaceId, nodeId, suffix), entry),
  remove: (spaceId: string, nodeId: string): void =>
    removeSpaceAccessEntry(nodeKey(spaceId, nodeId, suffix)),
})

const nodeContent = nodeEntryApi("")
const nodeStream = nodeEntryApi(":stream")
const nodeKeyring = nodeEntryApi(":keyring")

/** Look up a per-node invite-content access entry. */
export const getNodeAccessEntry = nodeContent.get
/** Persist an invite-content access entry for one node. */
export const saveNodeAccessEntry = nodeContent.save
/** Forget all three node-tier entries (content + stream + keyring). */
export function removeNodeAccessEntry(spaceId: string, nodeId: string): void {
  nodeContent.remove(spaceId, nodeId)
  nodeStream.remove(spaceId, nodeId)
  nodeKeyring.remove(spaceId, nodeId)
}

export const getNodeStreamAccessEntry = nodeStream.get
export const saveNodeStreamAccessEntry = nodeStream.save
export const removeNodeStreamAccessEntry = nodeStream.remove

export const getNodeKeyringAccessEntry = nodeKeyring.get
export const saveNodeKeyringAccessEntry = nodeKeyring.save
export const removeNodeKeyringAccessEntry = nodeKeyring.remove

// ── Bulk helpers ───────────────────────────────────────────────────────────────

/** A snapshot of the in-memory cache (for recovery routines). */
export function localSpaceAccessEntries(): SpaceAccessMap {
  return _cache
}

/** Extract the `CapMap` slice (member entries only) for writing to `_spaces.caps`. */
export function memberCapsFromStore(): CapMap {
  const out: CapMap = {}
  for (const [id, e] of Object.entries(_cache)) if (e.kind === "member") out[id] = e.cap
  return out
}

/** Extract the link-access slice for writing to `_spaces.pubAccess` (before sealing). */
export function linkAccessFromStore(): Record<string, LinkAccessPayload> {
  const out: Record<string, LinkAccessPayload> = {}
  for (const [id, e] of Object.entries(_cache)) {
    if (e.kind === "link") out[id] = { cap: e.cap, key: e.key, kemPriv: e.kemPriv, kemPub: e.kemPub, write: e.write }
  }
  return out
}

/** Drop the in-memory cache (on account switch / sign-out). */
export function clearSpaceAccessStore(): void {
  _cache = {}
  _activeKey = null
}

/** Drop one identity's persisted blob + reset in-memory state if currently active. */
export function clearPersistedSpaceAccess(userId: string, kv?: KvAdapter): void {
  const kvToUse = kv ?? _kv
  const key = keyFor(userId)
  if (kvToUse) void kvToUse.removeItem(key).catch(() => {})
  if (key === _activeKey) clearSpaceAccessStore()
}
