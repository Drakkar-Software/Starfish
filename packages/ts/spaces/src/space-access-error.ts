/**
 * `SpaceAccessError` — thrown when a space-access credential cannot be
 * resolved for a given space or node. Callers should catch this and prompt
 * the user to join / request access rather than treating it as a fatal error.
 */
export class SpaceAccessError extends Error {
  readonly spaceId: string
  readonly nodeId: string | undefined

  constructor(spaceId: string, nodeId?: string, message?: string) {
    super(message ?? `No access to ${nodeId ? `node ${nodeId} in ` : ""}space ${spaceId}`)
    this.name = "SpaceAccessError"
    this.spaceId = spaceId
    this.nodeId = nodeId
    // Preserve prototype chain for `instanceof` checks across transpiled class hierarchies.
    Object.setPrototypeOf(this, SpaceAccessError.prototype)
  }
}
