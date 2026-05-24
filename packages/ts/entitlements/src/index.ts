/**
 * `@drakkar.software/starfish-entitlements` — feature-slug entitlements extension.
 *
 * Public surface: the client-side `pullEntitlements` reader for a user's
 * feature-slug document, and the server-side `createEntitlementRoleEnricher`
 * factory that turns those slugs into `entitlement:<slug>` roles.
 *
 * The enricher plugs into the server through `SyncRouterOptions.roleEnricher`
 * (compose it with other enrichers via `composeEnrichers` from
 * `@drakkar.software/starfish-server`).
 */

export { pullEntitlements } from "./entitlements.js"
export type { PullEntitlementsOptions } from "./entitlements.js"

export { createEntitlementRoleEnricher } from "./entitlement-role-enricher.js"
export type { EntitlementRoleEnricherOptions } from "./entitlement-role-enricher.js"
