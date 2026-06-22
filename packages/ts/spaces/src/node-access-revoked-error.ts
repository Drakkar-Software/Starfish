/**
 * `NodeAccessRevokedError` — thrown when the server returns 403 on a node
 * keyring pull, indicating the requester's access was revoked (e.g. the desk
 * archived the ticket). Callers should treat this as a terminal signal and
 * stop polling rather than retrying.
 *
 * IMPORTANT: this is a standalone class, NOT a subclass of `SpaceAccessError`.
 * This prevents existing `catch (SpaceAccessError)` soft-paths from silently
 * swallowing it.
 */
export class NodeAccessRevokedError extends Error {
  readonly spaceId: string
  readonly nodeId: string

  constructor(spaceId: string, nodeId: string) {
    super(`Node ${nodeId} access revoked in space ${spaceId}`)
    this.name = "NodeAccessRevokedError"
    this.spaceId = spaceId
    this.nodeId = nodeId
    Object.setPrototypeOf(this, NodeAccessRevokedError.prototype)
  }
}
