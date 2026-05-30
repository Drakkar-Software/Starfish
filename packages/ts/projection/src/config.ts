import type { WriteEvent } from "@drakkar.software/starfish-protocol"

/**
 * The outcome of projecting a single source `WriteEvent` into a target list. A
 * projection function returns one of:
 *
 * - `{ id, value }` — UPSERT: if no entry with this `id` exists in the target
 *   list it is appended at the end; if one exists its `value` is replaced
 *   in place (keeping its position).
 * - `{ id, remove: true }` — REMOVE: drop the entry with this `id` from the list
 *   (a no-op if absent). Use this for a tombstone/soft-delete push, since the
 *   server has no delete route — a removal is signalled by a normal write whose
 *   body your mapping recognises as a deletion.
 * - `null` — IGNORE: this event does not affect the list.
 */
export type ProjectionOp =
  | { id: string; value: Record<string, unknown>; remove?: false }
  | { id: string; remove: true; value?: undefined }
  | null

/** One entry of a projection list. `id` is the stable key the mapping assigns;
 *  `value` is the app-supplied payload (e.g. `{ name }`). `id` is held alongside
 *  `value`, not merged into it, so a `value.id` field can never clobber it. */
export interface ProjectionItem {
  id: string
  value: Record<string, unknown>
}

/** The stored shape of a target list document's `data`: an insertion-ordered
 *  array of entries. Clients pull this one document to read the whole list. */
export interface ProjectionList {
  items: ProjectionItem[]
}

/**
 * Where a projection writes its list. Either a fixed storage key, or a function
 * of the event — return a key to route the entry into that list, or `null` to
 * ignore the event. Use the function form to shard a large view into many
 * bounded lists (e.g. one per tenant: `(e) => "products/" + e.params.tenantId`),
 * which keeps each list small and spreads write contention.
 */
export type ProjectionTarget = string | ((event: WriteEvent) => string | null)

/**
 * A single projection list: on every write to one of `source` collections,
 * `project` derives an entry op which the plugin folds into the target list
 * document (append / update-in-place / remove). The plugin owns the
 * read-modify-write against the store — the app supplies only the pure mapping.
 *
 * `project` MUST be a pure function of the event: it receives the `WriteEvent`
 * (which carries `collection`, `params`, optional `body`, `hash`, `timestamp`,
 * `identity`). The server populates `WriteEvent.body` for JSON pushes; `params`
 * is always present.
 */
export interface Projection {
  /** Source collection name(s) whose writes trigger this projection. */
  source: string | string[]
  /** The list document to maintain — a fixed key or a function of the event. */
  target: ProjectionTarget
  /** Pure mapping from a source write event to an entry upsert/remove/ignore. */
  project: (event: WriteEvent) => ProjectionOp | Promise<ProjectionOp>
}
