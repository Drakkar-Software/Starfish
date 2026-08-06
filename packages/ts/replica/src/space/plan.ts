/**
 * Pure planning step for a space-mirror sync cycle: given a space's current
 * object tree and the set of collection ids currently enabled, decide what
 * the channel needs to do this cycle. No network I/O and no `starfish-spaces`
 * dependency, so it is directly unit-testable.
 */

/** The subset of a space's object-tree node this planning logic reads. */
export interface ExistingSpaceNode {
  id: string
  type: string
}

export interface SpaceMirrorPlan {
  /** Collections that need a fresh node created before they can be written. */
  toCreate: string[]
  /** Collections to CAS-push a projection into this cycle — every currently
   *  enabled collection, whether its node is new or already existed. */
  toWrite: string[]
  /** Existing nodes whose collection was enabled before but is not anymore —
   *  their content gets cleared, not deleted (the node id itself stays valid
   *  so a later re-enable reuses it instead of accumulating orphaned nodes). */
  toClear: ExistingSpaceNode[]
}

/**
 * `existingNodes` should already be filtered to nodes this channel owns
 * (`type` present in `knownIds`) — an unrelated node sharing a type string by
 * coincidence isn't a real prerequisite this design defends against, but a
 * caller passing a space's FULL tree (including content this channel doesn't
 * manage, if the space is ever shared with other writers) must filter first
 * regardless — `knownIds` is exactly that filter, applied consistently to
 * both `enabledIds` and `existingNodes`.
 */
export function planSpaceMirror(
  existingNodes: readonly ExistingSpaceNode[],
  enabledIds: readonly string[],
  knownIds: ReadonlySet<string>,
): SpaceMirrorPlan {
  const enabled = new Set(enabledIds.filter((id) => knownIds.has(id)))
  const existingByType = new Map(existingNodes.map((n) => [n.type, n]))

  const toCreate: string[] = []
  const toWrite: string[] = []
  for (const id of enabled) {
    toWrite.push(id)
    if (!existingByType.has(id)) toCreate.push(id)
  }

  const toClear: ExistingSpaceNode[] = existingNodes.filter(
    (n) => knownIds.has(n.type) && !enabled.has(n.type),
  )

  return { toCreate, toWrite, toClear }
}
