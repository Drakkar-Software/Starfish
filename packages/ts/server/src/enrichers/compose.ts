import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

/**
 * Composes multiple `RoleEnricher` functions into one.
 *
 * All enrichers run in parallel (`Promise.all`) and their results are merged into
 * a single flat array. Use this when `SyncRouterOptions.roleEnricher` needs to
 * combine several enrichers — for example a group membership enricher together
 * with an entitlement enricher.
 *
 * ```ts
 * import { composeEnrichers, createGroupRoleEnricher, createEntitlementRoleEnricher } from "@drakkar.software/starfish-server"
 *
 * const roleEnricher = composeEnrichers(
 *   createGroupRoleEnricher({ store, membersPath: "groups/{groupId}/members", groupParam: "groupId" }),
 *   createEntitlementRoleEnricher({ store }),
 * )
 *
 * const router = createSyncRouter({ store, config, roleResolver, roleEnricher })
 * ```
 */
export function composeEnrichers(...enrichers: RoleEnricher[]): RoleEnricher {
  return async function composedEnricher(
    auth: AuthResult,
    params: Record<string, string>,
  ): Promise<string[]> {
    const results = await Promise.all(enrichers.map((e) => e(auth, params)))
    return results.flat()
  }
}
