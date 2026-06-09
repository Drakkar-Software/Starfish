# @drakkar.software/starfish-webhook

Inbound-webhook ingestion for Starfish. A generic, **format-agnostic** ingress that
lets an external system POST a message which lands in a Starfish collection — and,
optionally, an **end-to-end-encrypted** one, written by a party that holds no keys.

It ships **no** provider-specific adapters (no Slack/Discord/GitHub payload
schemas). You supply a `transform` that maps whatever JSON the sender posts onto
the document `data` to store. That keeps this a generic ingress, not a directory of
third-party formats.

## Two layers

| Layer | Surface | What it does |
|---|---|---|
| **Transport** | `createWebhookHandler`, `verifyHmac` | Authenticate the caller (HMAC), transform the payload, forward a normal push into the write pipeline. |
| **Sealed-write (E2EE)** | `generateSpaceWriteKey`, `sealDocument`, `openSealedDocument`, `isSealedBlob` | Let a keyless webhook encrypt into an E2EE space using only a published public key. |

## How a write happens

The handler never writes to storage directly. It builds a normal push `Request` and
hands it to a `dispatch` function — typically your `syncRouter.fetch`. So the target
collection's **RBAC, append-only handling and `afterWrite` hooks** (queuing, audit,
…) all run exactly as for a first-party client write.

```ts
import { Hono } from "hono"
import { createSyncRouter } from "@drakkar.software/starfish-server"
import { createWebhookHandler } from "@drakkar.software/starfish-webhook"

const syncRouter = createSyncRouter({ store, config, roleResolver /* … */ })

// `secret` is REQUIRED — it's the HMAC credential the external caller signs each
// request with. Read it explicitly so a missing env var fails loudly at boot rather
// than producing a route that rejects every call.
const ALERTS_SECRET = process.env.ALERTS_WEBHOOK_SECRET
if (!ALERTS_SECRET) throw new Error("ALERTS_WEBHOOK_SECRET must be set")

const webhook = createWebhookHandler({
  dispatch: (req) => syncRouter.fetch(req),
  routes: {
    // POST /webhook/alerts  →  appends to an append-only `events` collection
    alerts: {
      secret: ALERTS_SECRET,
      // optional replay window: sign `${ts}.${rawBody}` and bound the age
      timestampHeader: "x-webhook-timestamp",
      transform: ({ body }) => {
        const text = (body as { text?: unknown })?.text
        if (typeof text !== "string") return null // → 400
        return { t: "msg", e: { id: crypto.randomUUID(), text } }
      },
      target: "/push/events/inbox",
      // append-only collections enforce an author proof by default:
      author: { edPubHex: BOT_PUB, edPrivHex: BOT_PRIV },
    },
  },
})

const app = new Hono()
app.post("/webhook/:id", (c) => webhook(c.req.raw, c.req.param("id")))
app.route("/", syncRouter)
```

### Authentication

`verifyHmac` computes HMAC-SHA256 over the raw body (or `${timestamp}.${rawBody}`
when `timestampHeader` is set), hex-encoded, compared in constant time. `secret` is
**required** — it is the credential the external caller signs requests with (there is
no unauthenticated mode; an empty/missing secret fails closed). Also configure per
route: `signatureHeader` (default `x-webhook-signature`), `timestampHeader`,
`toleranceSeconds` (default 300).

> This is the generic, operator-configured HMAC model. A consumer that wants
> *self-service*, per-tenant credentials (each caller its own token, no shared
> operator secret) layers that on top — e.g. look the secret up per request from a
> store keyed by the route id — rather than hard-coding one `secret` here.

### Forwarding to a role-gated collection

For a target that is **not** public-write, attach the credential the push pipeline
expects via `forwardHeaders` (e.g. `{ Authorization: "Cap …" }`). The webhook then
authenticates the *external* caller (HMAC) and the *forwarded* write (cap)
independently.

## Sealed-write (E2EE)

Starfish's `delegated` mode encrypts content with a shared CEK every reader also
holds — so to write you must be able to read. A webhook should inject a message but
never decrypt history. Sealed-write makes that possible:

1. A space mints a write keypair with `generateSpaceWriteKey()`. The **public** half
   is published openly; the **private** half is distributed to members out of band
   (e.g. wrapped into the space keyring).
2. Set `seal: { recipientKemPubHex }` + a `sealer` keypair on the route. Each message
   is sealed at this edge, so a plain (`none`) collection stores only ciphertext —
   the server never sees the cleartext.
3. Members open it with `openSealedDocument(blob, privKey, { requireSealer })`.

The webhook holds the public write key and its own signing key — it can encrypt to
the space but cannot read anything sealed by anyone else. See
[`docs/ts/webhook/02-sealed-write.md`](../../../docs/ts/webhook/02-sealed-write.md).

## Trust boundary

For the E2EE guarantee to hold, the **sealing happens at the webhook receiver** (it
holds only the public key). External senders already transmit cleartext to whatever
URL they're given, so the receiver is the encryption edge: from it onward the
Starfish server stores ciphertext only, and only space members can read. Metadata
(timing, size, target) stays visible, as it is for any message.
