/**
 * Sealed resource-request inbox — the generic "request-to-create" pattern.
 *
 * A REQUESTER holds only the owner's **public identity link** (no authority, safe to
 * share openly). They seal a typed resource-creation request to the owner's KEM key
 * and append it anonymously to the owner's existing `inbox/{ownerId}/{shard}` collection.
 * The OWNER's reconciler trial-unseals pending requests, creates the requested node in
 * its space with its own owner cap, and seals a narrow per-node cap back to the requester's inbox.
 *
 * Security:
 *   - Offline binding: `verifyIdentityLinkBinding(ownerLink, session)` before sealing.
 *   - Sender authenticity: `sealed.entry.addedBy === req.requester.edPub`.
 *   - Accept/reject gate: owner decides; nothing lands in the space automatically.
 *   - Idempotency: nodes carry `meta.reqId`; `scanResourceRequests` skips fulfilled reqIds.
 */
import type { SealedBlob } from "./config.js"
import { sealToRecipient, unsealFromRecipient } from "./account-seal.js"
import { inboxShard, inboxShards, pullInbox } from "./inbox.js"
import { createKeyedStore } from "./keyed-store.js"
import { verifyIdentityLinkBinding, verifyIdentityLinkKeys } from "./identity-link.js"
import type { IdentityLink } from "./identity-link.js"
import { createNode, inviteToNode, acceptNodeInvite } from "./nodes.js"
import { verifyKemSig, signKemSig } from "./request-verify.js"
import { readObjectTree } from "./object-index.js"
import { randomId } from "@drakkar.software/starfish-protocol"
import type { Session } from "./session.js"
import type { ObjectNode } from "./config.js"
import type { ResourceRequest, ResourceGrant, ResourceReject } from "./token-types.js"
import { makeAnonSpaceClient } from "./client.js"

export type { ResourceRequest, ResourceGrant, ResourceReject }

/**
 * AES-GCM additional-data context binding for inbox seals.
 * Parameterized by `session.inboxAadNamespace` instead of hardcoded namespace.
 */
const inboxAad = (session: Session, recipientId: string, shard: string, kind: string) =>
  `${session.inboxAadNamespace}:${recipientId}:${shard}:${kind}`

/**
 * Trial-unseal an inbox element for `session.userId` with the kind-bound AAD.
 * Returns the plaintext, or `null` when the element isn't sealed to us.
 */
async function tryUnsealInbox(
  session: Session,
  sealed: SealedBlob,
  shard: string,
  mkind: string | undefined,
  defaultKind: string,
): Promise<string | null> {
  try {
    return await unsealFromRecipient(session, sealed, inboxAad(session, session.userId, shard, mkind ?? defaultKind))
  } catch {
    return null
  }
}

/**
 * Seal `obj` to a recipient and append it to their current-shard inbox.
 */
async function sealAppend(
  session: Session,
  recipientUserId: string,
  recipientKemPub: string,
  kind: string,
  obj: unknown,
): Promise<void> {
  const shard = inboxShard()
  const sealed = await sealToRecipient(
    session,
    recipientKemPub,
    JSON.stringify(obj),
    inboxAad(session, recipientUserId, shard, kind),
  )
  const element = { sealed, ts: Date.now(), mkind: kind } as unknown as Record<string, unknown>
  // Use an anonymous client for public-write inbox appends.
  const anonClient = makeAnonSpaceClient({ baseUrl: session.baseUrl, namespace: session.namespace })
  await anonClient.appendAnonymous(
    session.layout.inboxPush(recipientUserId, shard),
    element,
    { edPubHex: session.keys.edPub, edPrivHex: session.keys.edPriv },
  )
}

/**
 * Generic inbox scan: walk both shards, pull each element, trial-unseal it,
 * JSON-parse, and hand the parsed payload + its sealed envelope to `handle`.
 */
async function scanInbox(
  session: Session,
  defaultKind: string,
  handle: (parsed: unknown, sealed: SealedBlob) => void | Promise<void>,
): Promise<void> {
  for (const shard of inboxShards()) {
    const items = await pullInbox(session.accountClient, session.userId, shard, session)
    for (const item of items) {
      const payload = item?.data as Partial<InboxPayload> | undefined
      if (!payload?.sealed) continue

      const plaintext = await tryUnsealInbox(session, payload.sealed, shard, payload.mkind, defaultKind)
      if (plaintext === null) continue

      let parsed: unknown
      try {
        parsed = JSON.parse(plaintext)
      } catch {
        continue
      }
      await handle(parsed, payload.sealed)
    }
  }
}

// ── Owner-store: reqId → owner edPub ─────────────────────────────────────────

const reqIdOwnerStore = createKeyedStore<string>()

/** Record the owner edPub for a submitted request. */
export const saveReqIdOwner = (reqId: string, ownerEdPub: string): void => reqIdOwnerStore.set(reqId, ownerEdPub)
/** Snapshot the store for persistence across reloads. */
export const serializeReqIdOwnerStore = reqIdOwnerStore.serialize
/** Restore the store after a reload (additive). */
export const hydrateReqIdOwnerStore = reqIdOwnerStore.hydrate
/** Clear the store (e.g. on sign-out). */
export const clearReqIdOwnerStore = reqIdOwnerStore.clear

// ── Payload type ──────────────────────────────────────────────────────────────

interface InboxPayload {
  sealed: SealedBlob
  ts: number
  mkind?: string
}

// ── REQUESTER: submit a request ───────────────────────────────────────────────

/** Options for {@link submitResourceRequest}. */
export interface SubmitResourceRequestOptions {
  spaceId: string
  nodeType: string
  title: string
  meta?: Record<string, unknown>
  message?: string
}

/**
 * REQUESTER: send a sealed resource-creation request to an owner's inbox.
 *
 * Returns the `reqId` generated for this request — save it to track fulfilment.
 */
export async function submitResourceRequest(
  session: Session,
  ownerLink: IdentityLink,
  opts: SubmitResourceRequestOptions,
): Promise<{ reqId: string }> {
  if (ownerLink.ownerId === session.userId) throw new Error("Cannot send a request to yourself.")

  if (!(await verifyIdentityLinkBinding(ownerLink, session))) {
    throw new Error("That identity link is malformed — ownerId does not match edPub.")
  }
  await verifyIdentityLinkKeys(ownerLink, session)

  const reqId = randomId()
  const request: ResourceRequest = {
    v: 1,
    kind: "create-resource",
    reqId,
    spaceId: opts.spaceId,
    nodeType: opts.nodeType,
    title: opts.title,
    ...(opts.meta ? { meta: opts.meta } : {}),
    ...(opts.message ? { message: opts.message } : {}),
    requester: {
      userId: session.userId,
      edPub: session.keys.edPub,
      kemPub: session.keys.kemPub,
      kemSig: signKemSig(session.keys),
    },
  }

  saveReqIdOwner(reqId, ownerLink.edPub)
  await sealAppend(session, ownerLink.ownerId, ownerLink.kemPub, "request", request)

  return { reqId }
}

// ── OWNER: scan pending requests ──────────────────────────────────────────────

/** A pending request returned by {@link scanResourceRequests}, not yet fulfilled. */
export interface PendingRequest {
  req: ResourceRequest
  senderEdPub: string
}

/**
 * OWNER: scan this session's inbox for pending `create-resource` requests.
 */
export async function scanResourceRequests(
  session: Session,
  spaceIds?: ReadonlySet<string>,
): Promise<PendingRequest[]> {
  const treeCache = new Map<string, ObjectNode[]>()

  const out: PendingRequest[] = []
  await scanInbox(session, "request", async (parsed, sealed) => {
    const req = parsed as Partial<ResourceRequest>

    if (
      req.v !== 1 ||
      req.kind !== "create-resource" ||
      typeof req.reqId !== "string" ||
      typeof req.spaceId !== "string" ||
      typeof req.nodeType !== "string" ||
      typeof req.title !== "string" ||
      !req.requester ||
      typeof req.requester.edPub !== "string" ||
      typeof req.requester.kemPub !== "string" ||
      typeof req.requester.userId !== "string" ||
      typeof req.requester.kemSig !== "string"
    ) {
      return
    }

    if (sealed.entry.addedBy !== req.requester.edPub) return

    if ((await session.userIdFromEdPub(req.requester.edPub)) !== req.requester.userId) return

    if (!verifyKemSig(req.requester.edPub, req.requester.kemPub, req.requester.kemSig)) return

    if (spaceIds && !spaceIds.has(req.spaceId)) return

    if (!treeCache.has(req.spaceId)) {
      const tree = await readObjectTree(session, req.spaceId).catch(() => [])
      treeCache.set(req.spaceId, tree)
    }
    const tree = treeCache.get(req.spaceId) ?? []
    const alreadyFulfilled = tree.some(
      (n) => (n.meta as Record<string, unknown> | undefined)?.reqId === req.reqId,
    )
    if (alreadyFulfilled) return

    out.push({ req: req as ResourceRequest, senderEdPub: sealed.entry.addedBy })
  })
  return out
}

// ── OWNER: accept a request ───────────────────────────────────────────────────

/** Return value of an accepted {@link acceptResourceRequest}. */
export interface AcceptResult {
  spaceId: string
  nodeId: string
}

/**
 * OWNER: accept a pending resource request — create the node and grant the requester
 * a narrow per-node cap sealed back to their inbox.
 */
export async function acceptResourceRequest(
  session: Session,
  pending: PendingRequest,
  opts?: {
    create?: (session: Session, req: ResourceRequest) => Promise<{ nodeId: string }>
    write?: boolean
    enc?: boolean
  },
): Promise<AcceptResult> {
  const { req } = pending

  let nodeId: string
  if (opts?.create) {
    ;({ nodeId } = await opts.create(session, req))
  } else {
    const node = await createNode(session, req.spaceId, {
      type: req.nodeType,
      title: req.title,
      meta: { ...(req.meta ?? {}), reqId: req.reqId },
      access: "invite",
      enc: opts?.enc ?? false,
    })
    nodeId = node.id
  }

  const bundleJson = await inviteToNode(
    session,
    req.spaceId,
    nodeId,
    JSON.stringify(req.requester),
    { enc: opts?.enc ?? false },
    req.title,
    { isolated: true, write: opts?.write ?? true },
  )

  const grant: ResourceGrant = {
    v: 1,
    kind: "grant",
    reqId: req.reqId,
    spaceId: req.spaceId,
    nodeId,
    bundle: bundleJson,
  }
  await sealAppend(session, req.requester.userId, req.requester.kemPub, "grant", grant)

  return { spaceId: req.spaceId, nodeId }
}

// ── OWNER: reject a request ───────────────────────────────────────────────────

/**
 * OWNER: reject a pending request.
 */
export async function rejectResourceRequest(
  session: Session,
  pending: PendingRequest,
  reason?: string,
): Promise<void> {
  const { req } = pending
  const rejection: ResourceReject = {
    v: 1,
    kind: "reject",
    reqId: req.reqId,
    ...(reason ? { reason } : {}),
  }
  await sealAppend(session, req.requester.userId, req.requester.kemPub, "reject", rejection)
}

// ── REQUESTER: scan grants ────────────────────────────────────────────────────

/**
 * REQUESTER: scan this session's own inbox for resource grants (accepted requests).
 */
export async function scanResourceGrants(
  session: Session,
  opts?: { seenReqIds?: Set<string> },
): Promise<ResourceGrant[]> {
  const out: ResourceGrant[] = []
  const seenReqIds = opts?.seenReqIds ?? new Set<string>()
  await scanInbox(session, "grant", (parsed, sealed) => {
    const msg = parsed as Partial<ResourceGrant | ResourceReject>

    if (msg.v !== 1 || msg.kind !== "grant") return
    const g = msg as Partial<ResourceGrant>
    if (
      typeof g.reqId !== "string" ||
      typeof g.spaceId !== "string" ||
      typeof g.nodeId !== "string" ||
      typeof g.bundle !== "string"
    ) {
      return
    }

    const expectedOwnerEdPub = reqIdOwnerStore.get(g.reqId!)
    if (expectedOwnerEdPub && sealed.entry.addedBy !== expectedOwnerEdPub) return

    if (seenReqIds.has(g.reqId!)) return
    seenReqIds.add(g.reqId!)
    out.push(g as ResourceGrant)
  })
  return out
}

// ── REQUESTER: scan rejects ───────────────────────────────────────────────────

/**
 * REQUESTER: scan this session's own inbox for resource rejections.
 */
export async function scanResourceRejects(
  session: Session,
  opts?: { seenReqIds?: Set<string> },
): Promise<ResourceReject[]> {
  const out: ResourceReject[] = []
  const seenReqIds = opts?.seenReqIds ?? new Set<string>()
  await scanInbox(session, "reject", (parsed, sealed) => {
    const msg = parsed as Partial<ResourceReject>

    if (msg.v !== 1 || msg.kind !== "reject" || typeof msg.reqId !== "string") return

    const expectedOwnerEdPub = reqIdOwnerStore.get(msg.reqId)
    if (expectedOwnerEdPub && sealed.entry.addedBy !== expectedOwnerEdPub) return

    if (seenReqIds.has(msg.reqId)) return
    seenReqIds.add(msg.reqId)
    out.push(msg as ResourceReject)
  })
  return out
}

// ── REQUESTER: accept a grant ─────────────────────────────────────────────────

/**
 * REQUESTER: accept a resource grant — store the per-node cap and return the node reference.
 */
export async function acceptResourceGrant(
  session: Session,
  grant: ResourceGrant,
): Promise<{ spaceId: string; nodeId: string }> {
  const nodeId = await acceptNodeInvite(session, grant.bundle)
  return { spaceId: grant.spaceId, nodeId }
}
