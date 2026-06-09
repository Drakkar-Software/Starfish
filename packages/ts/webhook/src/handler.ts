/**
 * The inbound-webhook handler: authenticate → transform → (seal) → (sign) →
 * forward into the Starfish write pipeline.
 *
 * Framework-neutral — it takes a Web `Request` and returns a Web `Response`, so it
 * mounts under any fetch-based server (Hono, the Node `http` server via a small
 * adapter, a cloud function, …). It never writes to storage directly: it builds a
 * normal push `Request` and hands it to `dispatch` (typically `syncRouter.fetch`),
 * so the target collection's auth, append-only handling and `afterWrite` hooks all
 * run exactly as for a first-party client write.
 */

import { signAppendAuthor } from "@drakkar.software/starfish-protocol"
import { verifyHmac } from "./auth.js"
import { sealDocument } from "./sealed-write.js"
import type { WebhookHandlerOptions, WebhookRoute } from "./types.js"

const DEFAULT_ORIGIN = "http://webhook.local"

function json(status: number, body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function lowerHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {}
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value
  })
  return out
}

/** Strip the `/push/` action prefix to get the server's document key. */
function documentKeyFor(target: string): string {
  return target.replace(/^\/push\//, "")
}

async function buildPushBody(route: WebhookRoute, data: Record<string, unknown>): Promise<Record<string, unknown>> {
  // Option B: seal at this edge so the server stores only ciphertext.
  let stored: Record<string, unknown> = data
  if (route.seal) {
    if (!route.sealer) throw new Error("seal_config_missing_sealer")
    stored = (await sealDocument(data, route.seal.recipientKemPubHex, route.sealer)) as unknown as Record<
      string,
      unknown
    >
  }

  const body: Record<string, unknown> = { data: stored }
  if (route.author) {
    // Author proof is signed over the STORED bytes (post-seal), matching what the
    // server verifies and what a reader re-verifies after pulling.
    const proof = signAppendAuthor(
      documentKeyFor(route.target),
      stored,
      route.author.edPubHex,
      route.author.edPrivHex,
    )
    Object.assign(body, proof)
  } else {
    // No author proof → a regular create-if-absent push. Harmlessly ignored by
    // append-only collections (which never read baseHash).
    body.baseHash = null
  }
  return body
}

/**
 * Build the webhook ingestion handler. The returned function takes the inbound
 * `Request` and the `webhookId` (extracted from the route path by the host) and
 * resolves to the `Response` to send back to the caller.
 */
export function createWebhookHandler(opts: WebhookHandlerOptions) {
  const origin = opts.origin ?? DEFAULT_ORIGIN

  return async function handleWebhook(request: Request, webhookId: string): Promise<Response> {
    const route = opts.routes[webhookId]
    if (!route) return json(404, { error: "unknown_webhook" })
    if (request.method !== "POST") return json(405, { error: "method_not_allowed" })

    const raw = await request.text()
    const headers = lowerHeaders(request.headers)

    // Authentication is pluggable: a custom `authenticate` callback (no static secret),
    // or the built-in HMAC `secret`. A route with neither is a misconfiguration.
    if (route.authenticate) {
      let ok: boolean
      try {
        ok = await route.authenticate({ raw, headers, webhookId })
      } catch (e) {
        console.warn(`[starfish-webhook] authenticate threw for "${webhookId}":`, e)
        return json(500, { error: "auth_failed" })
      }
      if (!ok) return json(401, { error: "unauthorized" })
    } else if (route.secret) {
      const auth = await verifyHmac(
        {
          secret: route.secret,
          signatureHeader: route.signatureHeader,
          timestampHeader: route.timestampHeader,
          toleranceSeconds: route.toleranceSeconds,
        },
        raw,
        headers,
      )
      if (!auth.ok) return json(auth.status, { error: auth.error })
    } else {
      console.warn(`[starfish-webhook] route "${webhookId}" has neither secret nor authenticate`)
      return json(500, { error: "no_auth_configured" })
    }

    let parsedBody: unknown
    if (raw.length > 0) {
      try {
        parsedBody = JSON.parse(raw)
      } catch {
        // Leave undefined — a transform may still use `raw`.
      }
    }

    let data: Record<string, unknown> | null
    try {
      data = await route.transform({ body: parsedBody, raw, headers })
    } catch (e) {
      // Don't echo the exception text back to the caller; log it for the operator.
      console.warn(`[starfish-webhook] transform threw for "${webhookId}":`, e)
      return json(400, { error: "transform_failed" })
    }
    if (data == null) return json(400, { error: "rejected_by_transform" })

    let pushBody: Record<string, unknown>
    try {
      pushBody = await buildPushBody(route, data)
    } catch (e) {
      console.warn(`[starfish-webhook] failed to build push body for "${webhookId}":`, e)
      return json(500, { error: "ingest_failed" })
    }

    const pushRequest = new Request(`${origin}${route.target}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(route.forwardHeaders ?? {}) },
      body: JSON.stringify(pushBody),
    })
    return opts.dispatch(pushRequest)
  }
}
