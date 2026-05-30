import type { WriteEvent } from "@drakkar.software/starfish-protocol"

/**
 * The outcome of projecting a single source `WriteEvent` into the target
 * collection. A projection function returns one of:
 *
 * - `{ key, data }` — UPSERT: write `data` as the target document at storage key
 *   `key` (relative to the store root, i.e. the resolved `storagePath`).
 * - `{ key, delete: true }` — DELETE: remove the target document at `key`.
 * - `null` — IGNORE: this event does not affect the view.
 */
export type ProjectionResult =
  | { key: string; data: Record<string, unknown>; delete?: false }
  | { key: string; delete: true; data?: undefined }
  | null

/**
 * A single materialized view: on every write to one of `source` collections,
 * `project` derives a target document (or a deletion, or nothing). The plugin
 * owns the read-modify-write against the store — the app only supplies the pure
 * mapping.
 *
 * `project` MUST be a pure function of the event: it receives the `WriteEvent`
 * (which carries `collection`, `params`, optional `body`, `hash`, `timestamp`,
 * `identity`) and returns a {@link ProjectionResult}. To see the pushed document
 * body, the watched source collection must be configured with the queuing/
 * projection-visible body (the server populates `WriteEvent.body` for JSON
 * pushes); `params` is always present.
 */
export interface Projection {
  /** Source collection name(s) whose writes trigger this projection. */
  source: string | string[]
  /** Pure mapping from a source write event to a target upsert/delete/ignore. */
  project: (event: WriteEvent) => ProjectionResult | Promise<ProjectionResult>
}
