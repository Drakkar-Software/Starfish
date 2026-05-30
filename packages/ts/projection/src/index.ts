/**
 * `@drakkar.software/starfish-projection` — incremental-list extension.
 *
 * Public surface: the `Projection` list spec, its `ProjectionOp` outcome and the
 * stored `ProjectionItem`/`ProjectionList` shapes, and
 * `createProjectionServerPlugin` — a `ServerPlugin` whose `afterWrite` hook folds
 * each source write into a single target list document (append / update-in-place
 * / remove). Clients pull that one document to read the whole list. Pair the
 * target collection with `pullOnly: true` so only the projection writes it
 * (clients read it only).
 */

export type { Projection, ProjectionOp, ProjectionItem, ProjectionList, ProjectionTarget } from "./config.js"
export { createProjectionServerPlugin } from "./plugin.js"
export type { ProjectionPluginOptions } from "./plugin.js"
