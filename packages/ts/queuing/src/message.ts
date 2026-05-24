/**
 * Shape of the message published to the queue after a successful push.
 *
 * Always-present fields:
 * - `collection` — collection name
 * - `hash`       — SHA-256 hex hash of the stored document
 * - `timestamp`  — milliseconds since epoch when the push completed
 *
 * Conditionally present (controlled by `QueueConfig` flags):
 * - `params` — when `includeParams: true`
 * - `body`   — when `includeBody: true` (JSON collections only).
 *              Contains the `data` field from the push request body as sent by
 *              the client (before server-side sanitization of prototype-pollution keys).
 */
export interface QueueMessage {
  collection: string
  hash: string
  timestamp: number
  params?: Record<string, string>
  body?: Record<string, unknown>
}
