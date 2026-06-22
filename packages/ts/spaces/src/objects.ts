/**
 * Generic object-tree model — pure logic over a space's object index.
 *
 * A space's contents are {@link ObjectNode}s in one union-merged index doc at
 * `spaces/{spaceId}/objects/_index`. This module is the pure, testable core:
 * the tree builder + merge-artifact guards, breadcrumbs, ordering, and the node
 * reducers a `store.set` applies.
 *
 * Because the index is union-merged (per-node last-write-wins keyed on `updatedAt`),
 * the tree is eventually consistent — two devices can concurrently produce a cycle
 * or an orphan. The builder below is the single place those are repaired so every
 * consumer renders a well-formed tree.
 *
 * No domain types (room, category, task, …) are defined here. Apps define their own.
 */
import { randomId } from "@drakkar.software/starfish-protocol"
import type { ID, NodeAccess, ObjectNode, ObjectType } from "./config.js"

/** A node plus its resolved children — the shape a tree view renders. */
export interface ObjectTreeNode extends ObjectNode {
  depth: number
  children: ObjectTreeNode[]
}

function compareSiblings(a: ObjectNode, b: ObjectNode): number {
  if (a.order !== b.order) return a.order - b.order
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

/** The order value for a new node appended after `siblings`. */
export function nextOrder(siblings: ObjectNode[]): number {
  let max = 0
  for (const s of siblings) if (s.order > max) max = s.order
  return max + 1
}

/**
 * Build the render tree from a flat node list, repairing merge artifacts:
 *  - **archived** nodes (and their subtrees) are dropped.
 *  - **orphans** — a `parentId` that is missing or archived — reparent to root.
 *  - **cycles** — a node reachable from itself via `parentId` — reparent to root.
 *  - **siblings** sort by {@link compareSiblings} for cross-device determinism.
 */
export function buildTree(nodes: ObjectNode[], includeArchived = false): ObjectTreeNode[] {
  const live = includeArchived ? nodes : nodes.filter((n) => !n.archived)
  const byId = new Map<ID, ObjectNode>(live.map((n) => [n.id, n]))

  const effectiveParent = (n: ObjectNode): ID | null => {
    if (n.parentId == null) return null
    if (!byId.has(n.parentId)) return null
    const seen = new Set<ID>([n.id])
    let cur: ID | null = n.parentId
    while (cur != null) {
      if (seen.has(cur)) return null
      seen.add(cur)
      const parent = byId.get(cur)
      if (!parent) return null
      cur = parent.parentId
    }
    return n.parentId
  }

  const childrenOf = new Map<ID | null, ObjectNode[]>()
  for (const n of live) {
    const p = effectiveParent(n)
    const bucket = childrenOf.get(p) ?? []
    bucket.push(n)
    childrenOf.set(p, bucket)
  }

  function attach(parent: ID | null, depth: number): ObjectTreeNode[] {
    return (childrenOf.get(parent) ?? [])
      .slice()
      .sort(compareSiblings)
      .map((n): ObjectTreeNode => ({ ...n, depth, children: attach(n.id, depth + 1) }))
  }

  return attach(null, 0)
}

/** The root→node trail (inclusive) for breadcrumbs. Returns `[]` if unknown. */
export function breadcrumbs(nodes: ObjectNode[], id: ID): ObjectNode[] {
  const byId = new Map<ID, ObjectNode>(nodes.map((n) => [n.id, n]))
  const trail: ObjectNode[] = []
  const seen = new Set<ID>()
  let cur: ID | null = id
  while (cur != null && byId.has(cur) && !seen.has(cur)) {
    seen.add(cur)
    const node: ObjectNode = byId.get(cur)!
    trail.unshift(node)
    cur = node.parentId
  }
  return trail
}

/** The root→parent trail (EXCLUSIVE of the node itself). */
export function ancestors(nodes: ObjectNode[], id: ID): ObjectNode[] {
  return breadcrumbs(nodes, id).slice(0, -1)
}

/** The ids of a node and its whole subtree (for cascade-archive). */
export function subtreeIds(nodes: ObjectNode[], rootId: ID): Set<ID> {
  const childrenOf = new Map<ID | null, ID[]>()
  for (const n of nodes) {
    const bucket = childrenOf.get(n.parentId) ?? []
    bucket.push(n.id)
    childrenOf.set(n.parentId, bucket)
  }
  const out = new Set<ID>()
  const walk = (id: ID) => {
    if (out.has(id)) return
    out.add(id)
    for (const child of childrenOf.get(id) ?? []) walk(child)
  }
  walk(rootId)
  return out
}

// ── Node reducers (pure: ObjectNode[] → ObjectNode[]) ─────────────────────────

export interface NewObjectInput {
  type: ObjectType
  parentId?: ID | null
  title: string
  emoji?: string
  /** App-specific metadata passed through to node.meta. */
  meta?: Record<string, unknown>
  /** Provide to reuse an id (e.g. a node id derived elsewhere); else minted fresh. */
  id?: ID
  /**
   * Optional id prefix used when minting a new id. Defaults to `'obj-'`.
   * Pass `session.nodeIdPrefix` to use the configured prefix.
   */
  idPrefix?: string
  /** Who may reach this node. Absent ⇒ `'space'` (all space members). */
  access?: NodeAccess
  /** Whether the node's content is E2EE under its own per-node keyring. Absent ⇒ false. */
  enc?: boolean
}

/** Append a new node under `parentId` at the end of its sibling order. */
export function addObject(
  nodes: ObjectNode[],
  input: NewObjectInput,
  now: number,
): { nodes: ObjectNode[]; node: ObjectNode } {
  const parentId = input.parentId ?? null
  const siblings = nodes.filter((n) => n.parentId === parentId)
  const prefix = input.idPrefix ?? "obj-"
  const node: ObjectNode = {
    id: input.id ?? `${prefix}${randomId()}`,
    type: input.type,
    parentId,
    order: nextOrder(siblings),
    title: input.title,
    ...(input.emoji ? { emoji: input.emoji } : {}),
    updatedAt: now,
    ...(input.meta ? { meta: input.meta } : {}),
    ...(input.access && input.access !== "space" ? { access: input.access } : {}),
    ...(input.enc ? { enc: true as const } : {}),
  }
  return { nodes: [...nodes, node], node }
}

/** Map over `nodes`, stamping `changes(n)` + a fresh `updatedAt: now` onto each node
 * matching `match` and leaving the rest untouched. */
function updateNodes(
  nodes: ObjectNode[],
  match: (n: ObjectNode) => boolean,
  changes: (n: ObjectNode) => Partial<ObjectNode>,
  now: number,
): ObjectNode[] {
  return nodes.map((n) => (match(n) ? { ...n, ...changes(n), updatedAt: now } : n))
}

/** Patch a node's mutable metadata (title/emoji/meta/access/enc), bumping `updatedAt`. */
export function patchObject(
  nodes: ObjectNode[],
  id: ID,
  patch: Partial<Pick<ObjectNode, "title" | "emoji" | "meta" | "access" | "enc">>,
  now: number,
): ObjectNode[] {
  return updateNodes(nodes, (n) => n.id === id, () => patch, now)
}

/** Reparent a node (move in the tree). Rejects making a node its own descendant. */
export function reparentObject(
  nodes: ObjectNode[],
  id: ID,
  parentId: ID | null,
  now: number,
): ObjectNode[] {
  if (id === parentId) return nodes
  if (parentId != null && subtreeIds(nodes, id).has(parentId)) return nodes
  const siblings = nodes.filter((n) => n.parentId === parentId && n.id !== id)
  return updateNodes(nodes, (n) => n.id === id, () => ({ parentId, order: nextOrder(siblings) }), now)
}

/** Set explicit sibling order (drag-reorder). */
export function reorderObjects(
  nodes: ObjectNode[],
  orderById: Record<ID, number>,
  now: number,
): ObjectNode[] {
  return updateNodes(nodes, (n) => n.id in orderById, (n) => ({ order: orderById[n.id]! }), now)
}

/** Cascade-archive a node and its whole subtree (soft delete). */
export function archiveObject(nodes: ObjectNode[], id: ID, now: number): ObjectNode[] {
  const ids = subtreeIds(nodes, id)
  return updateNodes(nodes, (n) => ids.has(n.id), () => ({ archived: true }), now)
}
