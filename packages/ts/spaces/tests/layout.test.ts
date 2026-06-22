/**
 * Tests for `defaultSpaceLayout` — verifies that all path and scope
 * producers return the correct canonical octospaces values.
 */
import { describe, it, expect } from "vitest"
import { defaultSpaceLayout } from "../src/layout.js"

const SPACE = "sp-abc123"
const NODE = "obj-xyz789"
const USER = "deadbeef01020304"

describe("defaultSpaceLayout paths", () => {
  it("spacesPull includes /pull/ prefix", () => {
    expect(defaultSpaceLayout.spacesPull(USER)).toBe(`/pull/user/${USER}/_spaces`)
  })

  it("spacesPush includes /push/ prefix", () => {
    expect(defaultSpaceLayout.spacesPush(USER)).toBe(`/push/user/${USER}/_spaces`)
  })

  it("spaceAccessPull", () => {
    expect(defaultSpaceLayout.spaceAccessPull(SPACE)).toBe(`/pull/spaces/${SPACE}/_access`)
  })

  it("spaceAccessPush", () => {
    expect(defaultSpaceLayout.spaceAccessPush(SPACE)).toBe(`/push/spaces/${SPACE}/_access`)
  })

  it("objIndexPull", () => {
    expect(defaultSpaceLayout.objIndexPull(SPACE)).toBe(`/pull/spaces/${SPACE}/objects/_index`)
  })

  it("objIndexPush", () => {
    expect(defaultSpaceLayout.objIndexPush(SPACE)).toBe(`/push/spaces/${SPACE}/objects/_index`)
  })

  it("keyringName", () => {
    expect(defaultSpaceLayout.keyringName(SPACE)).toBe(`spaces/${SPACE}`)
  })

  it("keyringPull", () => {
    expect(defaultSpaceLayout.keyringPull(SPACE)).toBe(`/pull/spaces/${SPACE}/_keyring`)
  })

  it("keyringPush", () => {
    expect(defaultSpaceLayout.keyringPush(SPACE)).toBe(`/push/spaces/${SPACE}/_keyring`)
  })

  it("nodeKeyringName uses n/ prefix for node id", () => {
    expect(defaultSpaceLayout.nodeKeyringName(SPACE, NODE)).toBe(`spaces/${SPACE}/objects/n/${NODE}`)
  })

  it("nodeKeyringPull", () => {
    expect(defaultSpaceLayout.nodeKeyringPull(SPACE, NODE)).toBe(
      `/pull/spaces/${SPACE}/objects/n/${NODE}/_keyring`,
    )
  })

  it("inboxPull with shard", () => {
    expect(defaultSpaceLayout.inboxPull(USER, "2024-03")).toBe(`/pull/inbox/${USER}/2024-03`)
  })

  it("inboxPull defaults to 'default' shard", () => {
    expect(defaultSpaceLayout.inboxPull(USER)).toBe(`/pull/inbox/${USER}/default`)
  })

  it("objectDirPull with shard", () => {
    expect(defaultSpaceLayout.objectDirPull("public")).toBe(`/pull/_index/objects/public`)
  })

  it("objectDirPull defaults to 'public'", () => {
    expect(defaultSpaceLayout.objectDirPull()).toBe(`/pull/_index/objects/public`)
  })

  it("profilePull", () => {
    expect(defaultSpaceLayout.profilePull(USER)).toBe(`/pull/user/${USER}/profile`)
  })

  it("profilePush", () => {
    expect(defaultSpaceLayout.profilePush(USER)).toBe(`/push/user/${USER}/profile`)
  })
})

describe("defaultSpaceLayout scopes", () => {
  it("ownerScope grants all ops on wildcard", () => {
    const scope = defaultSpaceLayout.ownerScope()
    expect(scope.ops).toContain("write")
    expect(scope.collections).toContain("*")
  })

  it("spaceMemberScope read-only", () => {
    const scope = defaultSpaceLayout.spaceMemberScope(SPACE, false)
    expect(scope.ops).not.toContain("write")
    expect(scope.paths).toContain(`spaces/${SPACE}/**`)
  })

  it("spaceMemberScope write", () => {
    const scope = defaultSpaceLayout.spaceMemberScope(SPACE, true)
    expect(scope.ops).toContain("write")
  })

  it("nodeMemberScope uses objinv collection", () => {
    const scope = defaultSpaceLayout.nodeMemberScope(SPACE, NODE, true)
    expect(scope.collections).toEqual(["objinv"])
    expect(scope.paths!.some((p) => p.includes(NODE))).toBe(true)
  })

  it("nodeStreamScope uses objinvlog collection", () => {
    const scope = defaultSpaceLayout.nodeStreamScope(SPACE, NODE, true)
    expect(scope.collections).toEqual(["objinvlog"])
  })

  it("nodeKeyringScope grants read-only on nodekeyring", () => {
    const scope = defaultSpaceLayout.nodeKeyringScope(SPACE, NODE)
    expect(scope.ops).not.toContain("write")
    expect(scope.collections).toEqual(["nodekeyring"])
  })

  it("accountScope covers user + spaces + inbox paths", () => {
    const scope = defaultSpaceLayout.accountScope(USER)
    expect(scope.paths!.some((p) => p.includes(USER))).toBe(true)
    expect(scope.paths!.some((p) => p.includes("spaces/**"))).toBe(true)
    expect(scope.paths!.some((p) => p.includes("inbox"))).toBe(true)
  })
})
