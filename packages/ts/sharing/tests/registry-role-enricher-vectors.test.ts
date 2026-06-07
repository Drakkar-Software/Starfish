/**
 * Cross-language decision-table vectors for makeRegistryRoleEnricher.
 *
 * Shares `tests/test-vectors/registry-role-enricher.json` with the Python suite
 * (`packages/python/sharing/tests/test_registry_role_enricher_vectors.py`) so the
 * two implementations cannot drift on the registry/TOFU decision matrix. The
 * fail-closed (store-raises) and trailing-newline cases stay in
 * `registry-role-enricher.test.ts` — they can't be expressed as static data.
 */

import { describe, it, expect } from "vitest"
import { MemoryObjectStore } from "@drakkar.software/starfish-server"
import { makeRegistryRoleEnricher } from "../src/registry-role-enricher.js"
import vectors from "../../../../tests/test-vectors/registry-role-enricher.json"

interface VectorCase {
  name: string
  registry?: unknown
  registryRaw?: string
  allowTofu: boolean
  authIdentity: string
  id: string
  expected: string[]
}

describe("registry-role-enricher vectors", () => {
  for (const c of vectors.cases as VectorCase[]) {
    it(c.name, async () => {
      const store = new MemoryObjectStore(new Map())
      const path = vectors.registryPath.replace("{id}", c.id)
      if (c.registryRaw !== undefined) {
        await store.put(path, c.registryRaw)
      } else if (c.registry != null) {
        await store.put(path, JSON.stringify(c.registry))
      }

      const enricher = makeRegistryRoleEnricher(store, {
        idParam: vectors.idParam,
        registryPath: vectors.registryPath,
        ownerRole: vectors.ownerRole,
        memberRole: vectors.memberRole,
        allowTofu: c.allowTofu,
      })
      const roles = await enricher({ identity: c.authIdentity, roles: [] }, { [vectors.idParam]: c.id })
      expect(roles).toEqual(c.expected)
    })
  }
})
