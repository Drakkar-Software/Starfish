import { describe, it, expect } from "vitest"
import { withConflictMeta, createUnionMerge, timestampWinner } from "../src/resolvers.js"

describe("withConflictMeta", () => {
  it("detects conflicted fields", () => {
    const resolver = withConflictMeta((local, remote) => ({ ...remote, ...local }))
    const result = resolver(
      { a: 1, b: 2, c: 3 },
      { a: 1, b: 99, d: 4 },
    )

    expect(result.meta.conflictedFields).toContain("b")
    expect(result.meta.conflictedFields).toContain("c")
    expect(result.meta.conflictedFields).toContain("d")
    expect(result.meta.conflictedFields).not.toContain("a")
    expect(result.meta.timestamp).toBeGreaterThan(0)
  })

  it("identifies local winner", () => {
    const resolver = withConflictMeta((_local, _remote) => _local)
    const result = resolver({ x: 1 }, { x: 2 })

    expect(result.data).toEqual({ x: 1 })
    expect(result.meta.resolvedBy).toBe("local")
  })

  it("identifies remote winner", () => {
    const resolver = withConflictMeta((_local, _remote) => _remote)
    const result = resolver({ x: 1 }, { x: 2 })

    expect(result.data).toEqual({ x: 2 })
    expect(result.meta.resolvedBy).toBe("remote")
  })

  it("identifies merged result", () => {
    const resolver = withConflictMeta((local, remote) => ({
      ...local,
      ...remote,
      merged: true,
    }))
    const result = resolver({ a: 1 }, { b: 2 })

    expect(result.data).toEqual({ a: 1, b: 2, merged: true })
    expect(result.meta.resolvedBy).toBe("merged")
  })

  it("works with createUnionMerge", () => {
    const base = createUnionMerge()
    const resolver = withConflictMeta(base)
    const result = resolver(
      { items: [{ id: 1, name: "a", updatedAt: 100 }], timestamp: 100 },
      { items: [{ id: 1, name: "b", updatedAt: 200 }], timestamp: 200 },
    )

    expect(result.meta.conflictedFields).toContain("items")
    expect(result.data).toBeDefined()
  })

  it("works with timestampWinner", () => {
    const base = timestampWinner()
    const resolver = withConflictMeta(base)
    const result = resolver(
      { value: "old", timestamp: 100 },
      { value: "new", timestamp: 200 },
    )

    expect(result.data.value).toBe("new")
    expect(result.meta.resolvedBy).toBe("remote")
  })

  it("reports no conflicts when data is identical", () => {
    const resolver = withConflictMeta((local) => local)
    const result = resolver({ a: 1, b: 2 }, { a: 1, b: 2 })

    expect(result.meta.conflictedFields).toHaveLength(0)
    expect(result.meta.resolvedBy).toBe("local") // identical data = local wins
  })
})
