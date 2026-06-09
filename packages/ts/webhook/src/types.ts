/**
 * Public configuration shapes for the inbound-webhook ingestion extension.
 *
 * The extension is deliberately FORMAT-AGNOSTIC: it ships no knowledge of any
 * particular provider's payload (no Slack/Discord/GitHub adapters). An operator
 * supplies a {@link WebhookTransform} that maps whatever JSON the external system
 * posts onto the Starfish document `data` to store. That keeps the extension a
 * generic ingress, not a directory of third-party schemas.
 */

import type { SealerKeys } from "@drakkar.software/starfish-keyring"

/** Generic HMAC authentication for an inbound webhook caller. The signature is
 *  computed over the raw request body (or, when {@link timestampHeader} is set,
 *  over `${timestamp}.${rawBody}` so the timestamp is bound and replay-windowed). */
export interface HmacAuthConfig {
  /** Shared secret. Compared in constant time; never logged. */
  secret: string
  /** Header carrying the lowercase-hex HMAC-SHA256. Default `x-webhook-signature`. */
  signatureHeader?: string
  /** Optional header carrying a unix-seconds timestamp. When set, it is folded into
   *  the signed message AND its age is bounded by {@link toleranceSeconds}. */
  timestampHeader?: string
  /** Max accepted age (seconds) of {@link timestampHeader}. Default `300`. */
  toleranceSeconds?: number
}

/** The parsed inbound request handed to a {@link WebhookTransform}. */
export interface WebhookInput {
  /** The request body parsed as JSON, or `undefined` when the body was empty or
   *  not valid JSON (a transform may then fall back to {@link raw}). */
  body: unknown
  /** The exact request body bytes as a string (already HMAC-verified). */
  raw: string
  /** Request headers, keys lowercased. */
  headers: Record<string, string>
}

/**
 * Maps an inbound payload onto the Starfish document `data` to write. Return
 * `null` to reject the request (`400`). May be async. The returned object is
 * stored verbatim (after optional sealing) — the transform owns the target
 * collection's document shape.
 */
export type WebhookTransform = (
  input: WebhookInput,
) => Record<string, unknown> | null | Promise<Record<string, unknown> | null>

/** Sealed-write (E2EE) config — Option B. When present on a route, the transformed
 *  document is sealed to {@link recipientKemPubHex} (a published "space write key")
 *  before it is forwarded, so a `none`/plaintext collection stores ciphertext the
 *  server can never read. Only holders of the matching private key (distributed to
 *  members out of band, e.g. via a keyring) can open it. */
export interface WebhookSealConfig {
  /** The space write key: an X25519 public key (hex). Writers seal to it. */
  recipientKemPubHex: string
}

/** Context handed to a {@link WebhookAuthenticator}: the raw body, lowercased headers,
 *  and the route id — enough to verify a per-request credential (e.g. hash a bearer
 *  token from a header and look it up by `webhookId`). */
export interface WebhookAuthContext {
  raw: string
  headers: Record<string, string>
  webhookId: string
}

/** A custom authenticator, used INSTEAD of the built-in HMAC `secret`. Return `false`
 *  to reject (`401`). Lets a consumer authenticate per request with NO static secret —
 *  the self-service / per-tenant pattern (hash a presented token, look it up in a store
 *  by `webhookId`). */
export type WebhookAuthenticator = (ctx: WebhookAuthContext) => boolean | Promise<boolean>

/** One configured webhook endpoint, keyed by id in {@link WebhookHandlerOptions}.
 *
 * Authentication is REQUIRED but pluggable — provide exactly one of:
 *  - `secret` (+ optional `signatureHeader`/`timestampHeader`/`toleranceSeconds`): the
 *    built-in HMAC model, where the caller signs each request with a shared secret.
 *  - `authenticate`: a custom callback (no static secret), e.g. self-service per-tenant
 *    bearer tokens looked up from a store.
 * A route with neither is rejected at request time (`500`) — there is no
 * unauthenticated mode. The HMAC fields are inherited (all optional) from
 * {@link HmacAuthConfig}. */
export interface WebhookRoute extends Partial<HmacAuthConfig> {
  /** Custom authenticator, used instead of `secret`. See {@link WebhookAuthenticator}. */
  authenticate?: WebhookAuthenticator
  /** Maps the inbound payload to the document `data`. */
  transform: WebhookTransform
  /** Target Starfish push path, e.g. `/push/events/inbox` or
   *  `/push/spaces/abc/streams/xyz`. The document key is this minus `/push/`. */
  target: string
  /** Ed25519 author keypair. When set, the forwarded write carries a stored
   *  append-author proof (required by append-only collections with
   *  `requireAuthorSignature`). When unset, a regular create (`baseHash: null`)
   *  is sent instead. */
  author?: { edPubHex: string; edPrivHex: string }
  /** Option B: seal the document before forwarding. Requires {@link sealer}. */
  seal?: WebhookSealConfig
  /** Ed25519 keypair that SIGNS the seal entry (so readers can pin provenance via
   *  `requireSealer`). Required when {@link seal} is set. */
  sealer?: SealerKeys
  /** Extra headers attached to the forwarded push request — e.g. an
   *  `Authorization` cap for a role-gated target collection. */
  forwardHeaders?: Record<string, string>
}

/** Options for {@link createWebhookHandler}. */
export interface WebhookHandlerOptions {
  /** Configured webhooks, keyed by the id used in the request path. */
  routes: Record<string, WebhookRoute>
  /** Forwards the constructed push `Request` into the Starfish write pipeline —
   *  typically `syncRouter.fetch`. Reusing the real push path means the target
   *  collection's RBAC, append-only handling and `afterWrite` hooks (queuing,
   *  audit, …) all still apply, exactly as for a normal client write. */
  dispatch: (request: Request) => Promise<Response>
  /** Origin used to build the forwarded push URL. Default `http://webhook.local`. */
  origin?: string
}
