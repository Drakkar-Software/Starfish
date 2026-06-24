---
sidebar_position: 1
---

# Webhook ingestion — overview

`@drakkar.software/starfish-webhook` is an **inbound** ingress: it lets an external
system POST a payload that lands in a Starfish collection. It is the mirror image of
`starfish-queuing` (which emits change events *out* after a write); this accepts a
foreign request and turns it *into* a write.

It is deliberately **format-agnostic**. The package ships no Slack/Discord/GitHub
adapters. An operator supplies a `transform` mapping the inbound JSON onto the
document `data`. This keeps the extension a generic ingress rather than a registry
of third-party schemas.

## Design

Plugins cannot register HTTP routes (the sync router is built statically), so this
extension is **not** a `ServerPlugin`. It is a framework-neutral handler you mount
yourself and compose beside the sync router:

```
external POST ─▶ createWebhookHandler ─▶ dispatch(pushRequest) ─▶ syncRouter
                  │                                                  │
                  ├─ verifyHmac (authenticate the caller)            ├─ RBAC / roles
                  ├─ transform  (payload → document data)            ├─ append-only
                  ├─ seal?      (E2EE, optional)                     └─ afterWrite hooks
                  └─ sign?      (append-author proof)                   (queuing, audit…)
```

Because the handler forwards a **normal push** (via the injected `dispatch`,
typically `syncRouter.fetch`), every downstream behaviour — role checks, append-only
serialization, and `afterWrite` side effects like queuing — runs exactly as for a
first-party client write. The extension adds an ingress; it does not bypass the
pipeline.

## The flow, step by step

1. **Look up the route** by the `webhookId` in the path. Unknown → `404`.
2. **Authenticate** the caller. Pluggable: either the built-in HMAC `secret`
   (`verifyHmac` over the raw body, or `${timestamp}.${rawBody}` when a timestamp
   header is set) OR a custom `authenticate` callback (no static secret — e.g. a
   per-tenant token lookup). Bad/missing → `401`; a route with neither → `500`.
   Reason strings never echo the secret or the computed signature.
3. **Transform** the parsed payload into the document `data`. Returning `null`
   rejects the request (`400`) — use it to drop payloads you don't accept.
4. **Seal** (optional, Option B): encrypt the document to a published space write
   key so the server stores only ciphertext. See `02-sealed-write.md`.
5. **Sign** (optional): attach an append-author proof, required by append-only
   collections with `requireAuthorSignature` (the default). Without it, a regular
   create-if-absent push (`baseHash: null`) is sent instead.
6. **Forward** the constructed push `Request` to `dispatch` and return its response.

## Configuration

Provide exactly one auth mechanism — `secret` (built-in HMAC) **or** `authenticate`
(custom, no static secret):

```ts
interface WebhookRoute {
  // --- auth: pick ONE ---
  secret?: string                 // built-in HMAC shared secret (constant-time compared)
  signatureHeader?: string        // default "x-webhook-signature"
  timestampHeader?: string        // optional; enables a replay window
  toleranceSeconds?: number       // default 300
  authenticate?: (ctx: { raw; headers; webhookId }) => boolean | Promise<boolean>  // custom, no static secret
  // ----------------------
  transform: WebhookTransform     // (input) => document data | null
  target: string                  // e.g. "/push/events/inbox"
  author?: { edPubHex; edPrivHex } // append-author proof
  seal?: { recipientKemPubHex }   // E2EE — see sealed-write doc
  sealer?: { edPubHex; edPrivHex } // signs the seal; required when `seal` is set
  forwardHeaders?: Record<string,string> // e.g. an Authorization cap for a gated target
}
```

## Security notes

- **Authenticate the caller AND the write separately.** The route auth (HMAC `secret`
  or your custom `authenticate`) verifies the external sender; the forwarded push is
  authorized by the target collection's roles (use `forwardHeaders` to attach a cap for
  a non-public-write target).
- **For HMAC, prefer a timestamp header** (`timestampHeader`) so a captured request
  cannot be replayed indefinitely; tune `toleranceSeconds` to your clock skew.
- **No static operator secret needed.** Use `authenticate` to verify a per-tenant
  credential (e.g. a hashed bearer token from your store) so every caller crafts its
  own secret — no shared platform secret.
- **Rotate credentials per route.** Each webhook has its own; compromise of one never
  affects another.
- **Rate-limit** the mounted route as you would any public endpoint (the target
  collection's own `rateLimit` still applies to the forwarded push).
