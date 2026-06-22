/**
 * Tests for the pure object-tree algorithms in `src/objects.ts`.
 *
 * These are the easiest to test in isolation — no network, no session,
 * no crypto. Every function is a pure `ObjectNode[] → ObjectNode[]` transform.
 */
import { describe, it, expect } from "vitest"
import type { ObjectNode } from "../src/config.js"
import {
  buildTree,
  addObject,
  patchObject,
  reparentObject,
  reorderObjects,
  archiveObject,
  breadcrumbs,
  ancestors,
  subtreeIds,
  nextOrder,
} from "../src/objects.js"

// ── Helpers ────────────────────────────────────────────────────────────────────

function node(overrides: Partial<ObjectNode> & Pick<ObjectNode, "id">): ObjectNode {
  return {
    type: "page",
    parentId: null,
    order: 0,
    title: "Test",
    updatedAt: 1000,
    ...overrides,
  }
}

const NOW = 2000

// ── nextOrder ──────────────────────────────────────────────────────────────────

describe("nextOrder", () => {
  it("returns 1 for empty siblings", () => {
    expect(nextOrder([])).toBe(1)
  })

  it("returns max + 1", () => {
    expect(nextOrder([node({ id: "a", order: 3 }), node({ id: "b", order: 7 })])).toBe(8)
  })
})

// ── buildTree ─────────────────────────────────────────────────────────────────

describe("buildTree", () => {
  it("builds flat list with no parents", () => {
    const nodes = [node({ id: "a" }), node({ id: "b" })]
    const tree = buildTree(nodes)
    expect(tree).toHaveLength(2)
    expect(tree.every((n) => n.depth === 0)).toBe(true)
    expect(tree.every((n) => n.children.length === 0)).toBe(true)
  })

  it("attaches children to parents", () => {
    const nodes = [
      node({ id: "parent", order: 1 }),
      node({ id: "child", parentId: "parent", order: 1 }),
    ]
    const tree = buildTree(nodes)
    expect(tree).toHaveLength(1)
    expect(tree[0]!.children).toHaveLength(1)
    expect(tree[0]!.children[0]!.id).toBe("child")
    expect(tree[0]!.children[0]!.depth).toBe(1)
  })

  it("repairs orphans — missing parent → root", () => {
    const nodes = [node({ id: "orphan", parentId: "nonexistent" })]
    const tree = buildTree(nodes)
    expect(tree).toHaveLength(1)
    expect(tree[0]!.id).toBe("orphan")
  })

  it("repairs cycles — cyclic node → root", () => {
    const nodes = [
      node({ id: "a", parentId: "b" }),
      node({ id: "b", parentId: "a" }),
    ]
    const tree = buildTree(nodes)
    // Both land at root (no infinite loop)
    expect(tree).toHaveLength(2)
  })

  it("drops archived nodes by default", () => {
    const nodes = [node({ id: "a" }), node({ id: "b", archived: true })]
    expect(buildTree(nodes)).toHaveLength(1)
  })

  it("includes archived when includeArchived=true", () => {
    const nodes = [node({ id: "a" }), node({ id: "b", archived: true })]
    expect(buildTree(nodes, true)).toHaveLength(2)
  })

  it("sorts siblings deterministically by order then id", () => {
    const nodes = [
      node({ id: "z", order: 1 }),
      node({ id: "a", order: 1 }),
      node({ id: "m", order: 2 }),
    ]
    const tree = buildTree(nodes)
    expect(tree.map((n) => n.id)).toEqual(["a", "z", "m"])
  })
})

// ── addObject ─────────────────────────────────────────────────────────────────

describe("addObject", () => {
  it("appends a node to the flat list", () => {
    const { nodes, node: added } = addObject([], { type: "page", title: "A" }, NOW)
    expect(nodes).toHaveLength(1)
    expect(nodes[0]).toBe(added)
    expect(added.title).toBe("A")
    expect(added.updatedAt).toBe(NOW)
  })

  it("assigns next order after siblings", () => {
    const existing = [node({ id: "x", parentId: null, order: 5 })]
    const { node: added } = addObject(existing, { type: "page", title: "B" }, NOW)
    expect(added.order).toBe(6)
  })

  it("respects provided id", () => {
    const { node: added } = addObject([], { id: "custom-id", type: "page", title: "C" }, NOW)
    expect(added.id).toBe("custom-id")
  })

  it("respects idPrefix", () => {
    const { node: added } = addObject([], { type: "page", title: "D", idPrefix: "test-" }, NOW)
    expect(added.id).toMatch(/^test-/)
  })

  it("omits access field when access is 'space' (default)", () => {
    const { node: added } = addObject([], { type: "page", title: "E", access: "space" }, NOW)
    expect(added.access).toBeUndefined()
  })

  it("sets access when non-default", () => {
    const { node: added } = addObject([], { type: "page", title: "F", access: "public" }, NOW)
    expect(added.access).toBe("public")
  })
})

// ── patchObject ───────────────────────────────────────────────────────────────

describe("patchObject", () => {
  it("patches title and bumps updatedAt", () => {
    const before = [node({ id: "a", title: "Old" })]
    const after = patchObject(before, "a", { title: "New" }, NOW)
    expect(after[0]!.title).toBe("New")
    expect(after[0]!.updatedAt).toBe(NOW)
  })

  it("leaves other nodes unchanged", () => {
    const before = [node({ id: "a" }), node({ id: "b" })]
    const after = patchObject(before, "a", { title: "X" }, NOW)
    expect(after[1]!.updatedAt).toBe(before[1]!.updatedAt)
  })
})

// ── reparentObject ────────────────────────────────────────────────────────────

describe("reparentObject", () => {
  it("moves a node to a new parent", () => {
    const nodes = [
      node({ id: "parent" }),
      node({ id: "child", parentId: null }),
    ]
    const after = reparentObject(nodes, "child", "parent", NOW)
    expect(after.find((n) => n.id === "child")!.parentId).toBe("parent")
  })

  it("rejects making a node its own parent", () => {
    const nodes = [node({ id: "a" })]
    const after = reparentObject(nodes, "a", "a", NOW)
    expect(after).toEqual(nodes)
  })

  it("rejects making a node its own descendant", () => {
    const nodes = [
      node({ id: "parent" }),
      node({ id: "child", parentId: "parent" }),
    ]
    // Moving parent under child would create a cycle
    const after = reparentObject(nodes, "parent", "child", NOW)
    expect(after.find((n) => n.id === "parent")!.parentId).toBeNull()
  })
})

// ── reorderObjects ────────────────────────────────────────────────────────────

describe("reorderObjects", () => {
  it("updates order for matching ids", () => {
    const nodes = [node({ id: "a", order: 1 }), node({ id: "b", order: 2 })]
    const after = reorderObjects(nodes, { a: 10, b: 20 }, NOW)
    expect(after[0]!.order).toBe(10)
    expect(after[1]!.order).toBe(20)
  })
})

// ── archiveObject ─────────────────────────────────────────────────────────────

describe("archiveObject", () => {
  it("archives a node and its whole subtree", () => {
    const nodes = [
      node({ id: "root" }),
      node({ id: "child", parentId: "root" }),
      node({ id: "grandchild", parentId: "child" }),
      node({ id: "other" }),
    ]
    const after = archiveObject(nodes, "root", NOW)
    expect(after.find((n) => n.id === "root")!.archived).toBe(true)
    expect(after.find((n) => n.id === "child")!.archived).toBe(true)
    expect(after.find((n) => n.id === "grandchild")!.archived).toBe(true)
    expect(after.find((n) => n.id === "other")!.archived).toBeUndefined()
  })
})

// ── breadcrumbs / ancestors ───────────────────────────────────────────────────

describe("breadcrumbs", () => {
  it("returns root→node trail", () => {
    const nodes = [
      node({ id: "root" }),
      node({ id: "child", parentId: "root" }),
      node({ id: "leaf", parentId: "child" }),
    ]
    const trail = breadcrumbs(nodes, "leaf")
    expect(trail.map((n) => n.id)).toEqual(["root", "child", "leaf"])
  })

  it("returns [] for unknown id", () => {
    expect(breadcrumbs([], "nonexistent")).toEqual([])
  })

  it("breaks on cycles (does not loop)", () => {
    // Malformed data: a→b→a
    const nodes = [
      node({ id: "a", parentId: "b" }),
      node({ id: "b", parentId: "a" }),
    ]
    // Should not throw or loop — terminates early
    expect(() => breadcrumbs(nodes, "a")).not.toThrow()
  })
})

describe("ancestors", () => {
  it("excludes the node itself", () => {
    const nodes = [
      node({ id: "root" }),
      node({ id: "child", parentId: "root" }),
    ]
    const trail = ancestors(nodes, "child")
    expect(trail.map((n) => n.id)).toEqual(["root"])
  })
})

// ── subtreeIds ────────────────────────────────────────────────────────────────

describe("subtreeIds", () => {
  it("includes root and all descendants", () => {
    const nodes = [
      node({ id: "root" }),
      node({ id: "a", parentId: "root" }),
      node({ id: "b", parentId: "root" }),
      node({ id: "c", parentId: "a" }),
    ]
    const ids = subtreeIds(nodes, "root")
    expect(ids.has("root")).toBe(true)
    expect(ids.has("a")).toBe(true)
    expect(ids.has("b")).toBe(true)
    expect(ids.has("c")).toBe(true)
    expect(ids.size).toBe(4)
  })
})
