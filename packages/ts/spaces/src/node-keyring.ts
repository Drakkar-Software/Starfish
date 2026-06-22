/**
 * Per-node keyring helpers — E2EE primitive for invite-node encryption.
 *
 * Each `invite+enc` node carries its OWN keyring whose CEK is wrapped ONLY to
 * that node's participants, not the space-wide keyring. An external requester
 * can therefore read/write their content E2EE without holding the space key.
 *
 * These are thin wrappers over the generic keyring helpers in `client.ts`,
 * specialised to the node keyring path so call sites cannot accidentally target
 * the space keyring.
 *
 * INVARIANT: `ownerEnsureNodeKeyring` MUST run before `addNodeKeyringRecipient`.
 * Use `ensureNodeKeyringRecipient` to get both in the correct order.
 */
import { removeRecipient } from "@drakkar.software/starfish-keyring"
import type { Encryptor, StarfishClient } from "@drakkar.software/starfish-client"

import { openEncryptor, buildEncryptor, ownerEnsureKeyring, addKeyringRecipientCore } from "./client.js"
import type { DeviceKeys } from "./client.js"
import { ownerTrustedAdders } from "./session.js"
import type { Session } from "./session.js"
import { computeOwnerTrustedAdders } from "@drakkar.software/starfish-identities"

export { computeOwnerTrustedAdders }

/** A keyring recipient referenced by their X25519 KEM pubkey (hex). */
export interface NodeKeyringRecipient {
  subKem: string
  userId?: string
  label?: string
}

/**
 * Owner/creator side: create the node keyring if missing, then return an encryptor.
 */
export function ownerEnsureNodeKeyring(
  session: Session,
  spaceId: string,
  nodeId: string,
  trustedAdders: string[] = ownerTrustedAdders(session),
): Promise<Encryptor> {
  return ownerEnsureKeyring(
    session.contentClient,
    session.keys,
    session.layout.nodeKeyringPull(spaceId, nodeId),
    session.layout.nodeKeyringPush(spaceId, nodeId),
    trustedAdders,
  )
}

/**
 * Open the node keyring as a recipient (throws `SpaceAccessError` if absent
 * or if the caller is not a recipient).
 */
export function openNodeEncryptor(
  client: StarfishClient,
  keys: DeviceKeys,
  session: Pick<Session, "layout">,
  spaceId: string,
  nodeId: string,
  trustedAdders: string[],
): Promise<Encryptor> {
  return openEncryptor(client, keys, session.layout.nodeKeyringPull(spaceId, nodeId), trustedAdders)
}

/** Soft variant of {@link openNodeEncryptor}: resolves `null` instead of throwing.
 *
 * Propagates `NodeAccessRevokedError` when the server returns 403 — a revocation
 * signal that callers must handle explicitly rather than treating as "not ready".
 */
export function buildNodeEncryptor(
  client: StarfishClient,
  keys: DeviceKeys,
  session: Pick<Session, "layout">,
  spaceId: string,
  nodeId: string,
  trustedAdders: string[],
): Promise<Encryptor | null> {
  return buildEncryptor(client, keys, session.layout.nodeKeyringPull(spaceId, nodeId), trustedAdders, spaceId, nodeId)
}

/**
 * Add a recipient to the node keyring. The keyring MUST already exist (call
 * {@link ownerEnsureNodeKeyring} first). "Already present" is swallowed so
 * re-inviting the same KEM is idempotent.
 */
export function addNodeKeyringRecipient(
  session: Session,
  spaceId: string,
  nodeId: string,
  recipient: NodeKeyringRecipient,
  opts: { trustedAdders?: string[] } = {},
): Promise<void> {
  return addKeyringRecipientCore(
    session.contentClient,
    session.keys,
    session.layout.nodeKeyringName(spaceId, nodeId),
    recipient,
    opts.trustedAdders ?? ownerTrustedAdders(session),
  )
}

/**
 * Ensure the node keyring exists, then add a recipient — in that order.
 * Returns the owner's encryptor so the creator can immediately seal.
 */
export async function ensureNodeKeyringRecipient(
  session: Session,
  spaceId: string,
  nodeId: string,
  recipient: NodeKeyringRecipient,
  opts: { trustedAdders?: string[] } = {},
): Promise<Encryptor> {
  const enc = await ownerEnsureNodeKeyring(session, spaceId, nodeId, opts.trustedAdders)
  await addNodeKeyringRecipient(session, spaceId, nodeId, recipient, opts)
  return enc
}

/** Who to use as the keyring adder when revoking. Defaults to the session's own edPub. */
function adderOf(session: Session) {
  return { edPriv: session.keys.edPriv, edPub: session.keys.edPub, kemPriv: session.keys.kemPriv }
}

/**
 * REVOKE recipients from a node keyring: rotates to a NEW epoch, mints a fresh
 * CEK, and re-wraps ONLY to retained recipients. Removed parties lose access to
 * future messages (forward secrecy only). Returns the new epoch number.
 */
export async function removeNodeKeyringRecipient(
  session: Session,
  spaceId: string,
  nodeId: string,
  removeSubKems: string[],
  opts: { trustedAdders?: string[] } = {},
): Promise<{ newEpoch: number }> {
  return removeRecipient(
    session.contentClient,
    session.layout.nodeKeyringName(spaceId, nodeId),
    removeSubKems,
    adderOf(session),
    { trustedAdders: opts.trustedAdders ?? ownerTrustedAdders(session) },
  )
}
