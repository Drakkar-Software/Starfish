import { describe, expect, it } from "vitest"
import { planSpaceMirror } from "../src/space/plan.js"

// Mirrors the 5-collection registry OctoBot's mirror feature configures this
// generic planner with — ported 1:1 from the original hand-rolled
// `client/mirror/plan.ts`'s test suite (mirrorPlan.test.ts) to prove the
// generalization (fixed registry -> caller-supplied knownIds) is behavior-preserving.
const KNOWN = new Set([
  "user-accounts",
  "user-data",
  "user-strategies",
  "user-accounts-trading",
  "user-settings",
])

describe("planSpaceMirror", () => {
  it("plans to create and write every enabled collection when the space is empty", () => {
    const plan = planSpaceMirror([], ["user-accounts", "user-data"], KNOWN)
    expect(plan.toCreate.sort()).toEqual(["user-accounts", "user-data"])
    expect(plan.toWrite.sort()).toEqual(["user-accounts", "user-data"])
    expect(plan.toClear).toEqual([])
  })

  it("reuses an existing node for an already-mirrored collection — no re-create, still writes", () => {
    const existing = [{ id: "obj-1", type: "user-accounts" }]
    const plan = planSpaceMirror(existing, ["user-accounts"], KNOWN)
    expect(plan.toCreate).toEqual([])
    expect(plan.toWrite).toEqual(["user-accounts"])
    expect(plan.toClear).toEqual([])
  })

  it("clears a node whose collection was enabled before but is not anymore", () => {
    const existing = [
      { id: "obj-1", type: "user-accounts" },
      { id: "obj-2", type: "user-settings" },
    ]
    const plan = planSpaceMirror(existing, ["user-accounts"], KNOWN)
    expect(plan.toWrite).toEqual(["user-accounts"])
    expect(plan.toCreate).toEqual([])
    expect(plan.toClear).toEqual([{ id: "obj-2", type: "user-settings" }])
  })

  it("an empty enabled set clears every existing mirror node and creates/writes nothing", () => {
    const existing = [
      { id: "obj-1", type: "user-accounts" },
      { id: "obj-2", type: "user-data" },
    ]
    const plan = planSpaceMirror(existing, [], KNOWN)
    expect(plan.toCreate).toEqual([])
    expect(plan.toWrite).toEqual([])
    expect(plan.toClear).toEqual(existing)
  })

  it("ignores an unknown/unrecognized enabled id rather than trying to create a node for it", () => {
    const plan = planSpaceMirror([], ["user-accounts", "totally-not-a-collection"], KNOWN)
    expect(plan.toCreate).toEqual(["user-accounts"])
    expect(plan.toWrite).toEqual(["user-accounts"])
  })

  it("ignores an existing node whose type is not in knownIds (never plans to clear it)", () => {
    const existing = [{ id: "obj-1", type: "some-unrelated-node-type" }]
    const plan = planSpaceMirror(existing, [], KNOWN)
    expect(plan.toClear).toEqual([])
  })

  it("a re-enabled collection with a still-present (previously cleared) node reuses it, no re-create", () => {
    const existing = [{ id: "obj-1", type: "user-settings" }]
    const plan = planSpaceMirror(existing, ["user-settings"], KNOWN)
    expect(plan.toCreate).toEqual([])
    expect(plan.toWrite).toEqual(["user-settings"])
    expect(plan.toClear).toEqual([])
  })

  it("handles the full default set plus an opt-in collection together", () => {
    const plan = planSpaceMirror(
      [],
      ["user-accounts", "user-data", "user-strategies", "user-accounts-trading"],
      KNOWN,
    )
    expect(plan.toWrite.sort()).toEqual(
      ["user-accounts", "user-accounts-trading", "user-data", "user-strategies"],
    )
    expect(plan.toClear).toEqual([])
  })

  it("a fully independent knownIds set (not OctoBot's) plans correctly too", () => {
    const plan = planSpaceMirror([], ["notes", "contacts"], new Set(["notes", "contacts", "photos"]))
    expect(plan.toCreate.sort()).toEqual(["contacts", "notes"])
    expect(plan.toWrite.sort()).toEqual(["contacts", "notes"])
  })
})
