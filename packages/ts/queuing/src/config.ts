/**
 * Per-collection queue configuration. Owned by the queuing plugin — apps pass
 * a `{ [collectionName]: QueueConfig }` map to `createQueuingServerPlugin`.
 */
export interface QueueConfig {
  /** Subject/topic to publish to. Defaults to the collection name. */
  topic?: string
  /** Include the route path parameters in the published message. */
  includeParams: boolean
  /** Include the pushed `data` object in the message (JSON collections only). */
  includeBody?: boolean
}

/**
 * Coerce a loose config value into a `QueueConfig`.
 * - `true`        → `{ includeParams: false }`
 * - `false`/`null`/`undefined` → `undefined` (queue disabled for the collection)
 * - object        → used as-is
 */
export function coerceQueue(v: unknown): QueueConfig | undefined {
  if (v === true) return { includeParams: false }
  if (v === false || v == null) return undefined
  return v as QueueConfig
}
