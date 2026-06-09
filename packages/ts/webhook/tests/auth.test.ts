import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform, getCrypto } from "@drakkar.software/starfish-protocol"
import { verifyHmac } from "../src/auth.js"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: (data) => Buffer.from(data).toString("base64"),
        decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
})

const ENC = new TextEncoder()

/** Reference HMAC-SHA256 hex, computed independently of the module under test. */
async function sign(secret: string, message: string): Promise<string> {
  const key = await getCrypto().subtle.importKey(
    "raw",
    ENC.encode(secret) as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  )
  const sig = new Uint8Array(await getCrypto().subtle.sign("HMAC", key, ENC.encode(message) as BufferSource))
  return Array.from(sig, (b) => b.toString(16).padStart(2, "0")).join("")
}

describe("verifyHmac", () => {
  const secret = "s3cr3t"
  const raw = JSON.stringify({ text: "hello" })

  it("accepts a correct body signature", async () => {
    const headers = { "x-webhook-signature": await sign(secret, raw) }
    expect(await verifyHmac({ secret }, raw, headers)).toEqual({ ok: true })
  })

  it("rejects a missing signature", async () => {
    const res = await verifyHmac({ secret }, raw, {})
    expect(res).toEqual({ ok: false, status: 401, error: "missing_signature" })
  })

  it("fails closed on an empty secret (misconfiguration is not an open endpoint)", async () => {
    // The signature value is irrelevant — the empty-secret guard returns before any
    // comparison (and before importing a zero-length key).
    const res = await verifyHmac({ secret: "" }, raw, { "x-webhook-signature": "00" })
    expect(res).toEqual({ ok: false, status: 500, error: "webhook_misconfigured" })
  })

  it("rejects a wrong signature", async () => {
    const headers = { "x-webhook-signature": await sign("wrong-secret", raw) }
    const res = await verifyHmac({ secret }, raw, headers)
    expect(res).toEqual({ ok: false, status: 401, error: "invalid_signature" })
  })

  it("rejects a tampered body (signature was for different bytes)", async () => {
    const headers = { "x-webhook-signature": await sign(secret, raw) }
    const res = await verifyHmac({ secret }, raw + " ", headers)
    expect(res.ok).toBe(false)
  })

  it("honours a custom signature header name", async () => {
    const headers = { "x-hub-signature-256": await sign(secret, raw) }
    const res = await verifyHmac({ secret, signatureHeader: "X-Hub-Signature-256" }, raw, headers)
    expect(res).toEqual({ ok: true })
  })

  describe("with a timestamp header", () => {
    const cfg = { secret, timestampHeader: "x-webhook-timestamp", toleranceSeconds: 300 }

    it("accepts a fresh timestamped signature", async () => {
      const ts = String(Math.floor(Date.now() / 1000))
      const headers = {
        "x-webhook-timestamp": ts,
        "x-webhook-signature": await sign(secret, `${ts}.${raw}`),
      }
      expect(await verifyHmac(cfg, raw, headers)).toEqual({ ok: true })
    })

    it("rejects a stale timestamp (replay outside tolerance)", async () => {
      const ts = String(Math.floor(Date.now() / 1000) - 3600)
      const headers = {
        "x-webhook-timestamp": ts,
        "x-webhook-signature": await sign(secret, `${ts}.${raw}`),
      }
      const res = await verifyHmac(cfg, raw, headers)
      expect(res).toEqual({ ok: false, status: 401, error: "timestamp_out_of_tolerance" })
    })

    it("rejects a body-only signature when a timestamp is required", async () => {
      const ts = String(Math.floor(Date.now() / 1000))
      const headers = {
        "x-webhook-timestamp": ts,
        "x-webhook-signature": await sign(secret, raw), // signed without the ts prefix
      }
      const res = await verifyHmac(cfg, raw, headers)
      expect(res).toEqual({ ok: false, status: 401, error: "invalid_signature" })
    })

    it("rejects a missing timestamp", async () => {
      const headers = { "x-webhook-signature": await sign(secret, raw) }
      const res = await verifyHmac(cfg, raw, headers)
      expect(res).toEqual({ ok: false, status: 401, error: "missing_timestamp" })
    })
  })
})
