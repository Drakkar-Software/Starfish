/**
 * Per-collection queue configuration. Owned by the queuing plugin — apps pass
 * a `{ [collectionName]: QueueConfig }` map to `createQueuingServerPlugin`.
 */
export interface QueueConfig {
  /** Subject/topic to publish to. Defaults to the collection name. */
  topic?: string
  /**
   * Route path-param whose value is appended to the subject as a trailing token,
   * yielding a per-resource subject `<topic>.<value>` (e.g. `posts.changed.<postId>`)
   * so a broker/consumer can filter by resource (e.g. a NATS `<topic>.>`
   * subscription) without parsing the message body.
   *
   * The value is read straight from `WriteEvent.params`, so it works
   * **independently of `includeParams`**. It MUST fully match `subjectIdPattern`;
   * when missing, non-string, or carrying anything outside that charset, the base
   * subject is published unsuffixed. This re-validation is deliberate
   * defense-in-depth: the queuing layer must never emit a broker subject
   * containing `.`/`*`/`>` from an id that slipped through upstream gate drift.
   */
  subjectParam?: string
  /**
   * Regex the `subjectParam` value must fully match to be appended. Defaults to
   * {@link DEFAULT_SAFE_ID} (`^[a-zA-Z0-9_-]+$`). MUST NOT carry the `g` flag
   * (`.test()` would be stateful). Pass a pinned literal to keep the gate fixed
   * regardless of future library changes to the default.
   */
  subjectIdPattern?: RegExp
  /** Include the route path parameters in the published message. */
  includeParams: boolean
  /** Include the pushed `data` object in the message (JSON collections only). */
  includeBody?: boolean
  /**
   * Include the authenticated writer's identity (`WriteEvent.identity`) as
   * `identity` in the published message. Default `false` (off). Forwarding this
   * exposes *who* wrote each document to the queue/broker — metadata the server
   * otherwise never emits — so it is strictly per-collection opt-in.
   */
  includeIdentity?: boolean
}

/**
 * Default charset a `subjectParam` value must fully match before it is appended
 * to the publish subject. Admits only `[a-zA-Z0-9_-]` so the derived subject can
 * never carry a broker metacharacter (NATS `.`/`*`/`>`). No `g` flag — `.test()`
 * must be stateless.
 */
export const DEFAULT_SAFE_ID = /^[a-zA-Z0-9_-]+$/

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
