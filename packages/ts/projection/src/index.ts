/**
 * `@drakkar.software/starfish-projection` — materialized-view extension.
 *
 * Public surface: the `Projection` view spec and its `ProjectionResult` outcome,
 * and `createProjectionServerPlugin` — a `ServerPlugin` whose `afterWrite` hook
 * derives a document into a target collection after each successful push, with
 * upsert / delete / ignore semantics. Pair the target collection with
 * `pullOnly: true` so only the projection writes it (clients read/list only).
 */

export type { Projection, ProjectionResult } from "./config.js"
export { createProjectionServerPlugin } from "./plugin.js"
export type { ProjectionPluginOptions } from "./plugin.js"
