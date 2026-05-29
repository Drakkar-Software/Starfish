/**
 * Shape of the message published to the queue after a successful push.
 *
 * Always-present fields:
 * - `collection` — collection name
 * - `hash`       — SHA-256 hex hash of the stored document
 * - `timestamp`  — milliseconds since epoch when the push completed
 *
 * Conditionally present (controlled by `QueueConfig` flags):
 * - `params`   — when `includeParams: true`
 * - `body`     — when `includeBody: true` (JSON collections only).
 *                Contains the `data` field from the push request body as sent by
 *                the client (before server-side sanitization of prototype-pollution keys).
 * - `identity` — when `includeIdentity: true`. The authenticated writer's
 *                cap-bound userId (`WriteEvent.identity`). Off by default: it
 *                exposes *who* wrote off-box, so a collection must opt in.
 */
export interface QueueMessage {
  collection: string
  hash: string
  timestamp: number
  params?: Record<string, string>
  body?: Record<string, unknown>
  identity?: string
}
