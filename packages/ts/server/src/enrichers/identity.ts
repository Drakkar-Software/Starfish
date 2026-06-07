import type { RoleEnricher, AuthResult } from "../router/route-builder.js"

/**
 * Builds a {@link RoleEnricher} that grants a fixed `role` when the
 * authenticated `auth.identity` equals `identity`.
 *
 * Generalizes the common "platform admin" pattern (grant `"admin"` to the
 * platform's root userId) into a reusable primitive: any app that wants to
 * elevate one well-known identity to a named role can wire this enricher rather
 * than hand-rolling the comparison.
 *
 * Returns `[role]` on an exact, non-empty identity match and `[]` otherwise
 * (including when `auth.identity` is empty/anonymous). The match is on the
 * cap-cert-bound userId, so only the holder of the configured identity's key
 * material is ever elevated.
 *
 * Compose with other enrichers via {@link composeEnrichers}.
 *
 * ```ts
 * import { makeIdentityRoleEnricher } from "@drakkar.software/starfish-server"
 *
 * const adminEnricher = makeIdentityRoleEnricher(platformUserId, "admin")
 * ```
 */
export function makeIdentityRoleEnricher(identity: string, role: string): RoleEnricher {
  return async function identityRoleEnricher(
    auth: AuthResult,
    _params: Record<string, string>,
  ): Promise<string[]> {
    if (auth.identity && auth.identity === identity) return [role]
    return []
  }
}
