/**
 * Per-node creation, access management, and invite flows.
 *
 * Nodes are the atomic content units of a space. Each node carries two independent axes:
 *   - `access`: `'public' | 'space' | 'invite'` — who may reach the node.
 *   - `enc`:    `boolean` — whether content is E2EE under the SPACE-WIDE keyring.
 *
 * Invalid combo: `access:'public'` + `enc:true` is rejected outright.
 *
 * Encryption uses ONE space keyring (at `spaces/{spaceId}/_keyring`). Any space member
 * holding the keyring can decrypt ALL `enc` nodes in the space — the keyring is coarse-
 * grained by design. For `access:'invite'` + `enc:true` nodes, inviting someone to the
 * node also grants them the space key (and thus access to all enc content in the space).
 */
import type { RevocationEntry, RevocationList } from "@drakkar.software/starfish-protocol"
import { encodeLinkFragment, decodeLinkFragment, randomId } from "@drakkar.software/starfish-protocol"

import type { NodeAccess, ObjectNode, ObjectType } from "./config.js"
import { ensureSpaceKeyringRecipient, ownerEnsureSpaceKeyring, buildAuthHeaders } from "./client.js"
import type { Session } from "./session.js"
import {
  assertCapForMe,
  capNonce,
  ephemeralSubject,
  evictKeyringMember,
  mintCap,
  parseJoinRequest,
} from "./invite-helpers.js"
import { ensureNodeKeyringRecipient } from "./node-keyring.js"
import {
  saveNodeAccessEntry,
  saveNodeStreamAccessEntry,
  saveNodeKeyringAccessEntry,
  saveSpaceAccessEntry,
} from "./space-access-store.js"
import { sealToSelf } from "./account-seal.js"
import { createComposedStore } from "./keyed-store.js"
import { addObject } from "./objects.js"
import { updateObjectIndex } from "./object-index.js"
import { addSpaceMember, buildSpace } from "./registry.js"
import type { NodeInviteBundle, NodeInviteKind, NodeInviteLinkToken, StoredNodeInvite } from "./token-types.js"
import { RECIPIENT_LABEL_LEN } from "./layout.js"

export type { NodeInviteBundle, NodeInviteKind, NodeInviteLinkToken, StoredNodeInvite }

function recipientFor(subKem: string, userId: string) {
  return { subKem, userId, label: userId.slice(0, RECIPIENT_LABEL_LEN) }
}

// ── owner-side node invite store (nonces for revocation) ─────────────────────

// Keyed `${spaceId}:${nodeId}:${userId}` → invite.
const _nodeInviteStore = createComposedStore<StoredNodeInvite, [string, string, string]>(
  (spaceId, nodeId, userId) => `${spaceId}:${nodeId}:${userId}`,
)
const _niRaw = _nodeInviteStore.store

/** Record the caps minted for an isolated node invite (owner side). */
export const saveNodeInviteEntry = (
  spaceId: string, nodeId: string, userId: string, entry: StoredNodeInvite,
): void => _nodeInviteStore.for(spaceId, nodeId, userId).set(entry)
/** Retrieve the stored invite entry for a user on a node, or null if absent. */
export const getNodeInviteEntry = (
  spaceId: string, nodeId: string, userId: string,
): StoredNodeInvite | null => _nodeInviteStore.for(spaceId, nodeId, userId).get() ?? null
/** Clear all stored invite entries (for test isolation or sign-out). */
export const clearNodeInviteStore = (): void => {
  const raw = _niRaw.serialize()
  if (raw === "{}") return
  const keys = Object.keys(JSON.parse(raw) as Record<string, unknown>)
  for (const k of keys) _niRaw.clear(k)
}
/** Serialize the in-memory invite store for persistence. */
export const serializeNodeInviteStore = (): string => _niRaw.serialize()
/** Restore previously-serialized invite entries into the in-memory store. */
export const hydrateNodeInviteStore = (raw: string): void => _niRaw.hydrate(raw)

// ── createNode ────────────────────────────────────────────────────────────────

export interface CreateNodeInput {
  type: ObjectType
  title: string
  emoji?: string
  parentId?: string | null
  /** Who may reach this node. Default: `'space'`. */
  access?: NodeAccess
  /** Whether node content is E2EE under the space-wide keyring. Default: `false`. */
  enc?: boolean
  /** App-specific metadata. */
  meta?: Record<string, unknown>
}

/**
 * Create a new node in a space's object index.
 *
 * - Rejects the invalid combo `public+enc`.
 * - For `enc` nodes, ensures the space-wide keyring exists.
 * - Returns the created node as it was inserted into the index.
 */
export async function createNode(
  session: Session,
  spaceId: string,
  input: CreateNodeInput,
): Promise<ObjectNode> {
  const access = input.access ?? "space"
  const enc = input.enc ?? false
  if (access === "public" && enc) throw new Error("public+enc is not a valid combination.")

  const nodeId = `${session.nodeIdPrefix}${randomId()}`

  if (enc) {
    // Ensure the space-wide keyring exists (idempotent — minted once per space).
    await ownerEnsureSpaceKeyring(session, spaceId)
  }

  let createdNode: ObjectNode | null = null

  await updateObjectIndex(session, spaceId, (nodes, now) => {
    const { nodes: next, node } = addObject(
      nodes,
      {
        id: nodeId,
        type: input.type,
        title: input.title,
        ...(input.emoji ? { emoji: input.emoji } : {}),
        parentId: input.parentId ?? null,
        ...(input.meta ? { meta: input.meta } : {}),
        access,
        enc: enc || undefined,
      },
      now,
    )
    createdNode = next.find((n) => n.id === nodeId) ?? node
    return next
  })

  if (!createdNode) throw new Error("createNode: index update did not produce a node")

  // Mint the owner's per-node stream cap (objinvlog).
  const ownerStreamCap = await mintCap(
    session,
    { edPubHex: session.keys.edPub, kemPubHex: session.keys.kemPub, userIdHex: session.userId },
    "objinvlog",
    session.layout.nodeStreamScope(spaceId, nodeId, true),
  )
  saveNodeStreamAccessEntry(spaceId, nodeId, { kind: "member", cap: JSON.stringify(ownerStreamCap) })

  return createdNode
}

// ── setNodeAccess ─────────────────────────────────────────────────────────────

/**
 * Patch the `access`/`enc` axes of a node in the index.
 */
export async function setNodeAccess(
  session: Session,
  spaceId: string,
  nodeId: string,
  patch: { access?: NodeAccess; enc?: boolean },
): Promise<void> {
  if (patch.access === "public" && patch.enc) throw new Error("public+enc is not valid.")

  if (patch.enc) {
    await ownerEnsureSpaceKeyring(session, spaceId)
  }

  await updateObjectIndex(session, spaceId, (nodes, now) => {
    const idx = nodes.findIndex((n) => n.id === nodeId)
    if (idx < 0) return null
    const cur = nodes[idx]!

    const next: ObjectNode = { ...cur, updatedAt: now }

    if (patch.access !== undefined) {
      if (patch.access === "space") {
        delete (next as unknown as Record<string, unknown>).access
      } else {
        next.access = patch.access
      }
    }

    if (patch.enc !== undefined) {
      if (!patch.enc) {
        delete (next as unknown as Record<string, unknown>).enc
      } else {
        next.enc = true
      }
    }

    if (next.access === "public" && next.enc) throw new Error("public+enc is not valid.")

    const unchanged =
      next.access === cur.access &&
      (next.enc ?? false) === (cur.enc ?? false)
    if (unchanged) return null

    return nodes.map((n, i) => (i === idx ? next : n))
  })
}

// ── Direct invite ─────────────────────────────────────────────────────────────

/**
 * Owner: invite an identity to a specific node.
 *
 * - For `enc` nodes: adds the invitee to the space-wide keyring and mints a space-level member cap.
 * - For `invite+plaintext` nodes: mints both a space-level cap (index) and a narrow per-node cap.
 *
 * Returns the invite bundle JSON; pass to the invitee who calls `acceptNodeInvite`.
 */
export async function inviteToNode(
  session: Session,
  spaceId: string,
  nodeId: string,
  requestJson: string,
  node: { enc?: boolean },
  nodeName?: string,
  opts: { isolated?: boolean; write?: boolean } = {},
): Promise<string> {
  const req = await parseJoinRequest(requestJson, "Invalid join request", session)

  const isolated = !!opts.isolated
  const perNodeKeyring = !!node.enc && isolated
  const canWrite = opts.write !== false
  const subject = { edPubHex: req.edPub, kemPubHex: req.kemPub, userIdHex: req.userId }

  if (node.enc && !perNodeKeyring) {
    // LEGACY space-wide keyring path (non-isolated enc)
    await ensureSpaceKeyringRecipient(session, spaceId, recipientFor(req.kemPub, req.userId))
  }

  const bundle: NodeInviteBundle = {
    spaceId,
    nodeId,
    nodeName: nodeName ?? nodeId,
    kind: perNodeKeyring ? "node-enc" : (node.enc ? "space-enc" : "plaintext"),
  }

  if (perNodeKeyring) {
    // PER-NODE keyring: ensure + add the requester's KEM as a recipient
    await ensureNodeKeyringRecipient(session, spaceId, nodeId, recipientFor(req.kemPub, req.userId))
    bundle.keyringCap = await mintCap(session, subject, "nodekeyring", session.layout.nodeKeyringScope(spaceId, nodeId))
  }

  if (!isolated) {
    await addSpaceMember(session.accountClient, spaceId, session.userId, req.userId, session)
    bundle.cap = await mintCap(session, subject, "content", session.layout.spaceMemberScope(spaceId, canWrite))
  }

  if (!node.enc || perNodeKeyring) {
    bundle.nodeCap = await mintCap(session, subject, "objinv", session.layout.nodeMemberScope(spaceId, nodeId, canWrite))
    bundle.streamCap = await mintCap(session, subject, "objinvlog", session.layout.nodeStreamScope(spaceId, nodeId, canWrite))
  }

  // Retain cap nonces for future revocation (per-node-keyring invites only).
  if (perNodeKeyring) {
    const keyring = capNonce(bundle.keyringCap)
    const nodeCap = capNonce(bundle.nodeCap)
    const stream = capNonce(bundle.streamCap)
    saveNodeInviteEntry(spaceId, nodeId, req.userId, {
      edPub: req.edPub,
      kemPub: req.kemPub,
      caps: { ...(keyring && { keyring }), ...(nodeCap && { node: nodeCap }), ...(stream && { stream }) },
    })
  }

  return JSON.stringify(bundle)
}

// ── acceptNodeInvite ──────────────────────────────────────────────────────────

/** Set of valid NodeInviteBundle kind discriminators. */
const VALID_INVITE_KINDS: ReadonlySet<string> = new Set(["plaintext", "space-enc", "node-enc"])

/** The three per-node cap tiers carried in a NodeInviteBundle. */
const NODE_BUNDLE_TIERS = [
  { field: "nodeCap" as const, save: saveNodeAccessEntry },
  { field: "streamCap" as const, save: saveNodeStreamAccessEntry },
  { field: "keyringCap" as const, save: saveNodeKeyringAccessEntry },
] as const

export async function acceptNodeInvite(session: Session, bundleJson: string): Promise<string> {
  const bundle = JSON.parse(bundleJson) as Partial<NodeInviteBundle>
  if (!bundle.spaceId || !bundle.nodeId) throw new Error("Invalid node invite.")

  if (bundle.kind !== undefined && !VALID_INVITE_KINDS.has(bundle.kind)) {
    throw new Error(`Invalid node invite: unknown kind '${bundle.kind}'.`)
  }

  const assertForUs = (c: unknown, label: string): boolean =>
    assertCapForMe(
      c as { kind?: string; sub?: string } | undefined,
      session.keys.edPub,
      `Invalid node invite (${label}): unexpected cap kind.`,
      `This invite was issued for a different identity (${label}).`,
    )

  const spaceId = bundle.spaceId
  const nodeId = bundle.nodeId
  const hasSpaceCap = assertForUs(bundle.cap, "cap")
  const tierHas = NODE_BUNDLE_TIERS.map((t) => assertForUs(bundle[t.field], t.field))
  const hasNodeCap = tierHas[0]!
  if (!hasSpaceCap && !hasNodeCap) throw new Error("Invalid node invite.")

  if (hasSpaceCap) saveSpaceAccessEntry(spaceId, { kind: "member", cap: JSON.stringify(bundle.cap) })
  NODE_BUNDLE_TIERS.forEach((t, i) => {
    if (tierHas[i]) t.save(spaceId, nodeId, { kind: "member", cap: JSON.stringify(bundle[t.field]) })
  })

  return nodeId
}

// ── revokeNodeAccess ──────────────────────────────────────────────────────────

/**
 * Revoke a previously-issued isolated per-node-keyring invite.
 */
export async function revokeNodeAccess(
  session: Session,
  spaceId: string,
  nodeId: string,
  userId: string,
  opts: {
    generation: number
    priorRevoked?: RevocationEntry[]
    submitRevocation: (list: RevocationList) => Promise<void>
  },
): Promise<{ newEpoch?: number; revoked: boolean }> {
  const invite = getNodeInviteEntry(spaceId, nodeId, userId)
  if (!invite) {
    throw new Error(
      `revokeNodeAccess: no stored invite for ${userId} on node ${nodeId} — call saveNodeInviteEntry or use inviteToNode (which auto-stores for isolated enc nodes)`,
    )
  }
  if (!invite.caps.keyring) {
    throw new Error(
      `revokeNodeAccess: no keyring cap stored for ${userId} — only per-node-keyring (isolated enc) invites support revocation via this function`,
    )
  }

  const priorRevoked: RevocationEntry[] = [...(opts.priorRevoked ?? [])]
  if (invite.caps.node) {
    priorRevoked.push({ sub: invite.edPub, nonce: invite.caps.node.nonce, exp: invite.caps.node.exp })
  }
  if (invite.caps.stream) {
    priorRevoked.push({ sub: invite.edPub, nonce: invite.caps.stream.nonce, exp: invite.caps.stream.exp })
  }

  return evictKeyringMember(
    session.contentClient,
    session,
    session.layout.nodeKeyringName(spaceId, nodeId),
    { sub: invite.edPub, nonce: invite.caps.keyring.nonce, exp: invite.caps.keyring.exp, subKem: invite.kemPub },
    { generation: opts.generation, priorRevoked, submitRevocation: opts.submitRevocation },
  )
}

// ── Link-based node invite ────────────────────────────────────────────────────

export function encodeNodeInviteLink(origin: string, token: NodeInviteLinkToken): string {
  return encodeLinkFragment(origin, "join/node", token)
}

export function decodeNodeInviteLink(fragment: string): NodeInviteLinkToken {
  const raw = decodeLinkFragment<{ spaceId: string; nodeId: string; cap: unknown; key: string } & Partial<NodeInviteLinkToken>>(
    fragment,
    (tok: unknown) => {
      const t = tok as Record<string, unknown>
      return !!t && typeof t.spaceId === "string" && typeof t.nodeId === "string" && !!t.cap && typeof t.key === "string"
        ? (t as { spaceId: string; nodeId: string; cap: unknown; key: string } & Partial<NodeInviteLinkToken>)
        : null
    },
    "That node invite link is malformed or incomplete.",
  )
  return {
    v: 1,
    spaceId: raw.spaceId,
    nodeId: raw.nodeId,
    nodeName: raw.nodeName ?? raw.nodeId,
    cap: raw.cap,
    ...(raw.streamCap !== undefined ? { streamCap: raw.streamCap } : {}),
    ...(raw.keyringCap !== undefined ? { keyringCap: raw.keyringCap } : {}),
    key: raw.key,
    write: !!raw.write,
  }
}

/**
 * Owner: create a shareable invite link for a specific node.
 */
export async function createNodeInviteLink(
  session: Session,
  spaceId: string,
  nodeId: string,
  nodeName: string,
  node: { enc?: boolean },
  write: boolean,
  origin: string,
  opts: { isolated?: boolean; ttlSec?: number; nbf?: number; expiresAt?: number } = {},
): Promise<{ token: NodeInviteLinkToken; link: string }> {
  const { ek, userId: ephemeralUserId, subject } = await ephemeralSubject(session)

  const isolated = !!opts.isolated
  const perNodeKeyring = !!node.enc && isolated
  const capOpts = { ttlSec: opts.ttlSec, nbf: opts.nbf, expiresAt: opts.expiresAt }

  if (!isolated) {
    await addSpaceMember(session.accountClient, spaceId, session.userId, ephemeralUserId, session)
  }

  if (node.enc && !perNodeKeyring) {
    // LEGACY space-wide keyring path (non-isolated enc)
    await ensureSpaceKeyringRecipient(session, spaceId, recipientFor(ek.kemPub, ephemeralUserId))
  }

  let keyringCap: unknown
  if (perNodeKeyring) {
    await ensureNodeKeyringRecipient(session, spaceId, nodeId, recipientFor(ek.kemPub, ephemeralUserId))
    keyringCap = await mintCap(session, subject, "nodekeyring", session.layout.nodeKeyringScope(spaceId, nodeId), capOpts)
  }

  const cap =
    node.enc && !perNodeKeyring
      ? await mintCap(session, subject, "content", session.layout.spaceMemberScope(spaceId, write), capOpts)
      : await mintCap(session, subject, "objinv", session.layout.nodeMemberScope(spaceId, nodeId, write), capOpts)

  let streamCap: unknown
  if (!node.enc || perNodeKeyring) {
    streamCap = await mintCap(session, subject, "objinvlog", session.layout.nodeStreamScope(spaceId, nodeId, write), capOpts)
  }

  const token: NodeInviteLinkToken = {
    v: 1,
    spaceId,
    nodeId,
    nodeName,
    cap,
    ...(streamCap !== undefined ? { streamCap } : {}),
    ...(keyringCap !== undefined ? { keyringCap } : {}),
    key: ek.edPriv,
    write,
  }
  return { token, link: encodeNodeInviteLink(origin, token) }
}

/**
 * Any user: access a node by redeeming an invite link token.
 */
export async function joinNodeByLink(session: Session, token: NodeInviteLinkToken): Promise<string> {
  const accessPayload = { cap: token.cap, key: token.key, write: token.write }
  const sealed = await sealToSelf(session, JSON.stringify(accessPayload))
  const sealedStream =
    token.streamCap !== undefined
      ? await sealToSelf(session, JSON.stringify({ cap: token.streamCap, key: token.key, write: token.write }))
      : null
  const sealedKeyring =
    token.keyringCap !== undefined
      ? await sealToSelf(session, JSON.stringify({ cap: token.keyringCap, key: token.key, write: false }))
      : null

  const spaceEntry = buildSpace(token.nodeId, token.nodeName)
  const { updateSpacesDoc } = await import("./registry.js")
  await updateSpacesDoc(session.accountClient, session, (cur) => ({
    spaces: cur.spaces.some((s) => s.id === token.nodeId) ? cur.spaces : [...cur.spaces, spaceEntry],
    caps: cur.caps,
    pubAccess: {
      ...cur.pubAccess,
      [`${token.spaceId}:${token.nodeId}`]: sealed,
      ...(sealedStream ? { [`${token.spaceId}:${token.nodeId}:stream`]: sealedStream } : {}),
      ...(sealedKeyring ? { [`${token.spaceId}:${token.nodeId}:keyring`]: sealedKeyring } : {}),
    },
  }))

  saveNodeAccessEntry(token.spaceId, token.nodeId, {
    kind: "link",
    cap: token.cap,
    key: token.key,
    write: token.write,
  })
  if (token.streamCap !== undefined) {
    saveNodeStreamAccessEntry(token.spaceId, token.nodeId, {
      kind: "link",
      cap: token.streamCap,
      key: token.key,
      write: token.write,
    })
  }
  if (token.keyringCap !== undefined) {
    saveNodeKeyringAccessEntry(token.spaceId, token.nodeId, {
      kind: "link",
      cap: token.keyringCap,
      key: token.key,
      write: false,
    })
  }

  return token.nodeId
}

/**
 * Read an invite node's objinv content using only a link token (no Session required).
 */
export async function readNodeWithLinkCap(
  token: NodeInviteLinkToken,
  opts: { baseUrl: string; namespace: string },
): Promise<unknown> {
  // Build a minimal session-like object for buildAuthHeaders
  const path = `/pull/spaces/${token.spaceId}/objects/n/${token.nodeId}/content`
  const headers = await buildAuthHeaders(token.cap, token.key, "GET", path)
  const url = opts.baseUrl + (opts.namespace ? `/v1/${opts.namespace}` : "") + path
  const res = await fetch(url, { method: "GET", headers })
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`readNodeWithLinkCap failed: HTTP ${res.status}`)
  const json = await res.json() as { data?: unknown }
  return json.data ?? null
}

/**
 * Write to an invite node's objinv content using only a link token (no Session required).
 *
 * Uses optimistic-concurrency: seeds baseHash="" and adopts the server's `currentHash`
 * from the 409 response body on conflict, retrying up to MAX_ATTEMPTS times. This means:
 * - First write (doc absent): `"" → 200 (create)`.
 * - Subsequent writes: `"" → 409(H) → H → 200`.
 * - Degraded stored hash `""`: `"" == "" → 200 (heal)`.
 * No read permission is required — works with write-only caps.
 */
export async function writeNodeWithLinkCap(
  token: NodeInviteLinkToken,
  body: unknown,
  opts: { baseUrl: string; namespace: string },
): Promise<void> {
  const MAX_ATTEMPTS = 3
  const path = `/push/spaces/${token.spaceId}/objects/n/${token.nodeId}/content`
  const url = opts.baseUrl + (opts.namespace ? `/v1/${opts.namespace}` : "") + path
  let baseHash = ""
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const headers = await buildAuthHeaders(token.cap, token.key, "POST", path)
    const res = await fetch(url, {
      method: "POST",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ data: body, baseHash }),
    })
    if (res.ok) return
    if (res.status === 409) {
      const conflict = await res.json().catch(() => null) as { currentHash?: string } | null
      baseHash = conflict?.currentHash ?? ""
      continue
    }
    throw new Error(`writeNodeWithLinkCap failed: HTTP ${res.status}`)
  }
  throw new Error("writeNodeWithLinkCap: conflict after retries")
}
