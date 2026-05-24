import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

/**
 * Composes multiple `RoleEnricher` functions into one.
 *
 * All enrichers run in parallel (`Promise.all`) and their results are merged into
 * a single flat array. Use this when `SyncRouterOptions.roleEnricher` needs to
 * combine several application-level enrichers — for example a custom team-membership
 * enricher together with an entitlement enricher.
 *
 * ```ts
 * import { composeEnrichers, type RoleEnricher } from "@drakkar.software/starfish-server"
 * import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"
 *
 * const teamEnricher: RoleEnricher = async (auth, params) =>
 *   (await isTeamMember(auth.identity, params.teamId)) ? ["team-member"] : []
 *
 * const roleEnricher = composeEnrichers(
 *   teamEnricher,
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
