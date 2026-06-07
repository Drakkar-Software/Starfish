/**
 * `makeIdentityRoleEnricher`: grants a fixed role to a single configured
 * identity, empty otherwise.
 */

import { describe, it, expect } from "vitest"
import { makeIdentityRoleEnricher } from "../../src/enrichers/identity.js"
import type { AuthResult } from "../../src/router/route-builder.js"

const auth = (identity: string): AuthResult => ({ identity, roles: [] })

describe("makeIdentityRoleEnricher", () => {
  it("grants the role on an exact identity match", async () => {
    const enricher = makeIdentityRoleEnricher("alice-id", "admin")
    expect(await enricher(auth("alice-id"), {})).toEqual(["admin"])
  })

  it("returns empty on mismatch", async () => {
    const enricher = makeIdentityRoleEnricher("alice-id", "admin")
    expect(await enricher(auth("bob-id"), {})).toEqual([])
  })

  it("never elevates an empty/anonymous identity", async () => {
    const enricher = makeIdentityRoleEnricher("", "admin")
    expect(await enricher(auth(""), {})).toEqual([])
  })
})
