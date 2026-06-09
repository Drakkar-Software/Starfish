/**
 * `@drakkar.software/starfish-webhook` — inbound-webhook ingestion extension.
 *
 * A generic, FORMAT-AGNOSTIC ingress: it authenticates an external caller (HMAC),
 * maps the payload via an operator-supplied transform, and forwards a normal push
 * into the Starfish write pipeline (so RBAC, append-only and `afterWrite` hooks all
 * still apply). It ships no provider-specific adapters.
 *
 * Two layers:
 *  - Transport (`createWebhookHandler`, `verifyHmac`) — accept and forward a write.
 *  - Sealed-write (`generateSpaceWriteKey`, `sealDocument`, `openSealedDocument`) —
 *    let a keyless webhook encrypt into an E2EE space using only a published public
 *    key, while still being unable to read anything.
 */

export { createWebhookHandler } from "./handler.js"
export { verifyHmac } from "./auth.js"
export type { AuthResult } from "./auth.js"

export {
  generateSpaceWriteKey,
  sealDocument,
  openSealedDocument,
  isSealedBlob,
} from "./sealed-write.js"
export type { SpaceWriteKey, SealedBlob, SealerKeys } from "./sealed-write.js"

export type {
  HmacAuthConfig,
  WebhookInput,
  WebhookTransform,
  WebhookSealConfig,
  WebhookRoute,
  WebhookHandlerOptions,
} from "./types.js"
