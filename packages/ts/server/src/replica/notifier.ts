import * as crypto from "node:crypto"
import type { SubscriptionStore } from "./subscriber.js"
import { CONTENT_TYPE_JSON } from "../constants.js"

function sign(payload: Uint8Array, secret: string): string {
  const hmac = crypto.createHmac("sha256", secret)
  hmac.update(payload)
  return "sha256=" + hmac.digest("hex")
}

export function verifySignature(
  body: Uint8Array,
  signatureHeader: string,
  secret: string,
): boolean {
  const expected = sign(body, secret)
  if (expected.length !== signatureHeader.length) return false
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(signatureHeader),
  )
}

export class NotificationPublisher {
  private readonly subscriptionStore: SubscriptionStore
  private readonly webhookSecret?: string
  private readonly timeout: number

  constructor(
    subscriptionStore: SubscriptionStore,
    webhookSecret?: string,
    timeout = 5000,
  ) {
    this.subscriptionStore = subscriptionStore
    this.webhookSecret = webhookSecret
    this.timeout = timeout
  }

  async notify(
    collectionName: string,
    newHash: string,
    timestamp: number,
  ): Promise<void> {
    const subs = await this.subscriptionStore.listForCollection(collectionName)
    if (subs.length === 0) return

    const payload = JSON.stringify({
      collection: collectionName,
      hash: newHash,
      timestamp,
    })
    const bodyBytes = new TextEncoder().encode(payload)

    const headers: Record<string, string> = {
      "Content-Type": CONTENT_TYPE_JSON,
    }
    if (this.webhookSecret) {
      headers["X-Starfish-Signature"] = sign(bodyBytes, this.webhookSecret)
    }

    await Promise.allSettled(
      subs.map((sub) =>
        fetch(`${sub.webhookUrl.replace(/\/$/, "")}/replica/notify`, {
          method: "POST",
          headers,
          body: payload,
          signal: AbortSignal.timeout(this.timeout),
        }),
      ),
    )
  }
}
