/**
 * `@drakkar.software/starfish-restrictions` — identity action restrictions.
 *
 * A server-side extension that denies access for a list of identities, scoped to
 * the whole server, a namespace, a collection, or a single action (pull / push /
 * list). Identity lists are static arrays or callbacks, and may also be declared
 * statically in the serializable `SyncConfig` (`restrictions` fields).
 *
 * Plug it into the server through `SyncRouterOptions.plugins` via the `authorize`
 * hook it contributes:
 *
 * ```ts
 * import { createRestrictionsPlugin } from "@drakkar.software/starfish-restrictions"
 *
 * createSyncRouter({
 *   store, config, roleResolver,
 *   plugins: [defaultServerPlugin, createRestrictionsPlugin({ config })],
 * })
 * ```
 */

export {
  createRestrictionsPlugin,
  restrictionsFromConfig,
} from "./restrictions-plugin.js"
export type {
  RestrictionsPluginOptions,
  RestrictionRule,
  RestrictionScope,
  RestrictionAction,
  IdentitySource,
} from "./restrictions-plugin.js"
