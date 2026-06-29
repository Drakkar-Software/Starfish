/**
 * Space and node access resolver.
 *
 * Encryption is per-node (each node carries an `enc` flag) but keyed under ONE
 * space-wide keyring at `spaces/{spaceId}/_keyring`. All `enc` nodes in a space
 * share the same CEK; `access` gates *fetching*, the keyring gates *decryption*.
 *
 * Two entry points:
 *   - `getSpaceClient`  — returns the right StarfishClient for member-gated
 *     space docs (index, _access). No encryptor.
 *   - `getNodeAccess`   — resolves the (client, encryptor) for a specific node's
 *     CONTENT. Encryptor is null for plaintext nodes; for enc nodes the encryptor
 *     opens the SPACE keyring (not a per-node keyring).
 *
 * Resolution order for `getNodeAccess`:
 *   1. Per-node link entry  → sign as ephemeral identity; encryptor from space keyring.
 *   2. Per-node member entry → open space keyring as recipient.
 *   3. Space-level link entry → same client; open space keyring if enc.
 *   4. Space-level member entry → open space keyring if enc.
 *   5. No entry, owner        → mint space keyring if enc; plain client otherwise.
 *   6. No entry, non-owner   → SpaceAccessError if enc; plain client otherwise.
 */
import type { Encryptor, StarfishClient } from "@drakkar.software/starfish-client"

import { runCas } from "./cas-retry.js"
import {
  buildEncryptor,
  makeSpaceClient,
  openEncryptor,
  ownerEnsureKeyring,
} from "./client.js"
import type { DeviceKeys } from "./client.js"
import { buildNodeEncryptor, openNodeEncryptor } from "./node-keyring.js"
import type { Session } from "./session.js"
import { ownerTrustedAdders } from "./session.js"
import {
  getNodeAccessEntry,
  getNodeKeyringAccessEntry,
  getNodeStreamAccessEntry,
  getSpaceAccessEntry,
} from "./space-access-store.js"
import type { SpaceAccessEntry } from "./space-access-store.js"
import { SpaceAccessError } from "./space-access-error.js"
import type { NodeAccess } from "./config.js"

// Re-export so existing importers keep reaching SpaceAccessError through this module.
export { SpaceAccessError }

export interface NodeAccessHandle {
  encryptor: Encryptor | null
  client: StarfishClient
  /** True when opened as the space OWNER (may seed / mint the space keyring). */
  isOwnerOpen: boolean
  /**
   * Atomically write a document: pull for hash → decrypt → mutate → encrypt → push.
   * Retries up to 3× on ConflictError (same CAS semantics as `updateObjectIndex`).
   * The mutator receives the current decrypted data (null for a new doc) and returns
   * the next data to write, or null to skip the push (no-op).
   */
  push(
    pullPath: string,
    pushPath: string,
    mutator: (cur: Record<string, unknown> | null) => Record<string, unknown> | null,
  ): Promise<void>
}

const cache = new Map<string, Promise<NodeAccessHandle>>()

// Space-wide encryptor cache: one _keyring pull per (userId, spaceId) for all
// non-invite enc nodes. Per-node CONTENT entries (invite+enc, e.g. tickets) have
// their own per-node keyrings and go through resolveNodeKeyringHandle — not cached here.
// Null results and rejections are NOT cached (access state may change within a session).
const spaceEncryptorCache = new Map<string, Promise<Encryptor | null>>()

/** Drop every cached handle and space encryptor (on account switch — keys are per-identity). */
export function clearNodeAccessCache(): void {
  cache.clear()
  spaceEncryptorCache.clear()
}

/** @internal Build a fully-featured `NodeAccessHandle` that owns CAS-push + encryption. */
export function makeHandle(
  client: StarfishClient,
  encryptor: Encryptor | null,
  isOwnerOpen: boolean,
): NodeAccessHandle {
  return {
    client,
    encryptor,
    isOwnerOpen,
    push: async (pullPath, pushPath, mutator) => {
      await runCas(async () => {
        const res = await client.pull(pullPath).catch(() => null) as
          | { data: Record<string, unknown>; hash: string }
          | null
        const baseHash = res?.hash || null
        const cur = baseHash
          ? (encryptor ? await encryptor.decrypt(res!.data) : res!.data)
          : null
        const next = mutator(cur)
        if (next === null) return
        const payload = encryptor ? await encryptor.encrypt(next) : next
        await client.push(pushPath, payload, baseHash)
      })
    },
  }
}

/**
 * Build the StarfishClient + cap-issuer for a stored access entry. Link entries sign
 * as the ephemeral identity; member entries present their cap JSON; no entry falls back
 * to `session.contentClient` (identity-level, server authorizes by role). Shared by every
 * resolver below.
 */
function resolveEntryClient(
  entry: SpaceAccessEntry | null | undefined,
  session: Session,
): { client: StarfishClient; capIss?: string } {
  if (entry?.kind === "link") {
    return {
      client: makeSpaceClient(entry.cap, entry.key, {
        baseUrl: session.baseUrl,
        namespace: session.namespace,
      }),
    }
  }
  if (entry?.kind === "member") {
    const cap = JSON.parse(entry.cap) as { iss?: string }
    return {
      client: makeSpaceClient(cap, session.keys.edPriv, {
        baseUrl: session.baseUrl,
        namespace: session.namespace,
      }),
      capIss: cap.iss,
    }
  }
  return { client: session.contentClient }
}

/** Trusted-adder set for opening a space keyring: the cap issuer, else the registry
 *  owner, else the session's own owner keys. */
function resolveTrustedAdders(
  capIss: string | undefined,
  reg: { owner: string | null } | null | undefined,
  session: Session,
): string[] {
  return capIss ? [capIss] : reg?.owner ? [reg.owner] : ownerTrustedAdders(session)
}

/**
 * Return the right StarfishClient for reading/writing member-gated space docs
 * (e.g. the `_index`, `_access`). Spaces are always plaintext — no encryptor.
 */
export function getSpaceClient(spaceId: string, session: Session): StarfishClient {
  return resolveEntryClient(getSpaceAccessEntry(spaceId), session).client
}

/**
 * Return the StarfishClient for a node's append-log STREAM (`objinvlog`).
 *
 * A `member` cap covers exactly one collection. `objinvlog` is explicitly excluded from
 * `spaceMemberScope` AND `nodeMemberScope` (which covers only `objinv`), so neither the
 * node content entry nor the space entry can reach the stream — presenting either cap
 * would get a server 403. Only the dedicated stream entry (`nodeStreamScope`) carries
 * the right collection scope. For non-invite members (space members, owner) who have no
 * per-node stream entry, `session.contentClient` signs at the identity level and the server
 * authorizes via space-member role (same as for `objlog`).
 */
export function getNodeStreamClient(spaceId: string, nodeId: string, session: Session): StarfishClient {
  return resolveEntryClient(getNodeStreamAccessEntry(spaceId, nodeId), session).client
}

/**
 * Pick the KEM keypair to use when opening the space keyring for a given access entry.
 *
 * Link entries carry the EPHEMERAL recipient keypair minted by `createSpaceInviteLink` —
 * that ephemeral kemPub is what was added to the keyring, so the joiner's own device keys
 * are NOT keyring recipients. Member entries (and legacy link entries that predate 0.8.6,
 * which lack the ephemeral KEM) fall back to `session.keys`, preserving existing behaviour.
 */
function decryptKeysFor(entry: SpaceAccessEntry | null | undefined, session: Session): DeviceKeys {
  if (entry?.kind === "link" && entry.kemPriv && entry.kemPub) {
    return { edPriv: entry.key, edPub: "", kemPriv: entry.kemPriv, kemPub: entry.kemPub }
  }
  return session.keys
}

/**
 * Resolve the (content client, node-keyring encryptor) for a PER-NODE-keyring E2EE node
 * (`access:'invite' + enc`, e.g. an ticket). The CEK lives in the node's OWN
 * keyring (`nodekeyring`), never the space keyring.
 *
 *  - Isolated requester: holds a per-node keyring cap (read) + content/stream caps; opens
 *    the keyring with its cap client and ephemeral/own keys.
 *  - Space member / owner: holds no per-node entry but IS a keyring recipient (added at
 *    create / on assignment); opens via `session.contentClient` (space:member read) + own keys.
 *
 * `soft` returns null (instead of throwing) when the keyring isn't open-able yet.
 */
async function resolveNodeKeyringHandle(
  session: Session,
  spaceId: string,
  nodeId: string,
  reg: { owner: string | null; members?: string[] } | null,
  soft: boolean,
): Promise<NodeAccessHandle | null> {
  const krEntry = getNodeKeyringAccessEntry(spaceId, nodeId)
  const nodeEntry = getNodeAccessEntry(spaceId, nodeId)

  // Content client (objinv / ticket-info): requester → node content cap; member/owner → contentClient.
  const contentClient = resolveEntryClient(nodeEntry, session).client
  // Keyring client (read `nodekeyring`): requester → keyring cap; member/owner → contentClient.
  const kr = resolveEntryClient(krEntry, session)
  const krKeys = decryptKeysFor(krEntry, session)

  // trustedAdders = the keyring creator (ticket owner). From our cap issuer when we hold a
  // member cap, else the registry owner, else our own keys (owner self-open).
  const trustedAdders = resolveTrustedAdders(kr.capIss, reg, session)

  const isOwnerOpen = reg != null ? reg.owner === session.userId : krEntry == null

  if (soft) {
    const encryptor = await buildNodeEncryptor(kr.client, krKeys, session, spaceId, nodeId, trustedAdders)
    if (!encryptor) return null
    return makeHandle(contentClient, encryptor, isOwnerOpen)
  }
  const encryptor = await openNodeEncryptor(kr.client, krKeys, session, spaceId, nodeId, trustedAdders)
  return makeHandle(contentClient, encryptor, isOwnerOpen)
}

/**
 * Resolve the right (client, encryptor) for a node's CONTENT, opening and
 * caching on first use.
 *
 * `node` carries `{ access?, enc? }` — the plaintext flags from the index.
 * `reg` is the space's access record if already known; used to determine
 * ownership. Pass null if unknown.
 */
export function getNodeAccess(
  spaceId: string,
  nodeId: string,
  node: { access?: NodeAccess; enc?: boolean },
  session: Session,
  reg?: { owner: string | null; members: string[] } | null,
): Promise<NodeAccessHandle> {
  const cacheKey = `${spaceId}:${nodeId}`
  const hit = cache.get(cacheKey)
  if (hit) return hit

  const p = (async (): Promise<NodeAccessHandle> => {
    // Per-node-keyring E2EE (invite+enc, e.g. tickets): open the NODE keyring, NOT the
    // space-wide keyring. Hard variant: openNodeEncryptor throws on missing access.
    if (node.access === "invite" && node.enc) {
      const handle = await resolveNodeKeyringHandle(session, spaceId, nodeId, reg ?? null, false)
      return handle as NodeAccessHandle
    }

    // Prefer a per-node entry, fall back to the space-level entry for the client.
    const nodeEntry = getNodeAccessEntry(spaceId, nodeId)
    const spaceEntry = getSpaceAccessEntry(spaceId)
    const activeEntry = nodeEntry ?? spaceEntry

    // Build the client + cap issuer.
    const { client, capIss } = resolveEntryClient(activeEntry, session)

    const isOwnerOpen =
      reg != null ? reg.owner === session.userId : activeEntry == null

    // Plaintext node — no keyring needed.
    if (!node.enc) {
      return makeHandle(client, null, isOwnerOpen)
    }

    // E2EE node — resolve the SPACE-WIDE keyring (cached per userId:spaceId).
    const spacePullPath = session.layout.keyringPull(spaceId)
    const trustedAdders = resolveTrustedAdders(capIss, reg, session)

    if (activeEntry?.kind === "member" || activeEntry?.kind === "link") {
      const spaceEncKey = `${session.userId}:${spaceId}`
      let spaceEncPromise = spaceEncryptorCache.get(spaceEncKey)
      if (!spaceEncPromise) {
        const raw = openEncryptor(client, decryptKeysFor(activeEntry, session), spacePullPath, trustedAdders)
        // Widened type: openEncryptor always resolves non-null but may throw; rejections
        // are cleared so a retry can re-open the keyring.
        const p2: Promise<Encryptor | null> = raw.catch((err: unknown) => {
          spaceEncryptorCache.delete(spaceEncKey)
          throw err
        }) as Promise<Encryptor | null>
        spaceEncryptorCache.set(spaceEncKey, p2)
        spaceEncPromise = p2
      }
      const encryptor = await spaceEncPromise
      return makeHandle(client, encryptor, false)
    }

    // No access entry — owner mints/opens the keyring; non-owner errors.
    const owner = reg?.owner ?? null
    const members = reg?.members ?? []
    if (owner !== null && owner !== session.userId) {
      throw new SpaceAccessError(
        members.includes(session.userId)
          ? "You're a member of this space, but the space key isn't on this device yet — ask the owner to invite you."
          : "You don't have access to this node.",
      )
    }
    const encryptor = await ownerEnsureKeyring(
      session.contentClient,
      session.keys,
      spacePullPath,
      session.layout.keyringPush(spaceId),
      ownerTrustedAdders(session),
    )
    return makeHandle(session.contentClient, encryptor, true)
  })()

  cache.set(cacheKey, p)
  p.catch(() => cache.delete(cacheKey))
  return p
}

/**
 * SOFT resolve — normally never mints a keyring, never throws on missing access.
 * Returns null when the identity has no usable access for the node yet.
 *
 * When `reg` is provided and the caller is the SPACE OWNER (`reg.owner ===
 * session.userId`) but no keyring exists yet, the owner self-heals by minting
 * the keyring on the spot (idempotent).
 */
export async function buildNodeAccess(
  session: Session,
  spaceId: string,
  nodeId: string,
  node: { access?: NodeAccess; enc?: boolean },
  reg?: { owner: string | null; members?: string[] } | null,
): Promise<{ client: StarfishClient; encryptor: Encryptor | null } | null> {
  // Per-node-keyring E2EE (invite+enc): open the NODE keyring softly.
  if (node.access === "invite" && node.enc) {
    const handle = await resolveNodeKeyringHandle(session, spaceId, nodeId, reg ?? null, true)
    return handle ? { client: handle.client, encryptor: handle.encryptor } : null
  }

  const nodeEntry = getNodeAccessEntry(spaceId, nodeId)
  const spaceEntry = getSpaceAccessEntry(spaceId)
  const activeEntry = nodeEntry ?? spaceEntry

  const { client, capIss } = resolveEntryClient(activeEntry, session)
  const trustedAdders = resolveTrustedAdders(capIss, null, session)

  if (!node.enc) return { client, encryptor: null }

  // Soft-open the SPACE-WIDE keyring.
  const spacePullPath = session.layout.keyringPull(spaceId)
  const encryptor = await buildEncryptor(client, decryptKeysFor(activeEntry, session), spacePullPath, trustedAdders)
  if (encryptor) return { client, encryptor }

  // No keyring found. If the caller is the owner, self-heal by minting the keyring.
  if (reg != null && reg.owner === session.userId) {
    const mintedEncryptor = await ownerEnsureKeyring(
      session.contentClient,
      session.keys,
      spacePullPath,
      session.layout.keyringPush(spaceId),
      ownerTrustedAdders(session),
    )
    return { client: session.contentClient, encryptor: mintedEncryptor }
  }

  return null
}
