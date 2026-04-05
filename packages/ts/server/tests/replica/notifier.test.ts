import { describe, it, expect } from "vitest"
import { verifySignature } from "../../src/replica/notifier.js"

describe("verifySignature", () => {
  it("verifies correct HMAC signature", () => {
    const body = new TextEncoder().encode('{"collection":"test","hash":"abc","timestamp":1000}')
    const secret = "my-secret"

    // Generate expected signature
    const crypto = require("node:crypto")
    const hmac = crypto.createHmac("sha256", secret)
    hmac.update(body)
    const sig = "sha256=" + hmac.digest("hex")

    expect(verifySignature(body, sig, secret)).toBe(true)
  })

  it("rejects wrong signature", () => {
    const body = new TextEncoder().encode("hello")
    expect(verifySignature(body, "sha256=wrong", "secret")).toBe(false)
  })

  it("rejects signature with wrong length", () => {
    const body = new TextEncoder().encode("hello")
    expect(verifySignature(body, "short", "secret")).toBe(false)
  })
})
