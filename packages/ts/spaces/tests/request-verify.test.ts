/**
 * Tests for `signKemSig` and `verifyKemSig`.
 */
import { describe, it, expect } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { bytesToHex, hexToBytes } from "@drakkar.software/starfish-keyring"
import { signKemSig, verifyKemSig } from "../src/request-verify.js"

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes)
  globalThis.crypto.getRandomValues(buf)
  return bytesToHex(buf)
}

describe("signKemSig / verifyKemSig", () => {
  it("signs and verifies a KEM pubkey", () => {
    const edPriv = randomHex(32)
    const edPub = bytesToHex(ed25519.getPublicKey(hexToBytes(edPriv)))
    const kemPub = randomHex(32)

    const sig = signKemSig({ kemPub, edPriv })
    expect(verifyKemSig(edPub, kemPub, sig)).toBe(true)
  })

  it("returns false for a wrong edPub", () => {
    const edPriv = randomHex(32)
    const edPub = bytesToHex(ed25519.getPublicKey(hexToBytes(edPriv)))
    const wrongEdPub = bytesToHex(ed25519.getPublicKey(hexToBytes(randomHex(32))))
    const kemPub = randomHex(32)

    const sig = signKemSig({ kemPub, edPriv })
    expect(verifyKemSig(wrongEdPub, kemPub, sig)).toBe(false)
  })

  it("returns false for a wrong kemPub", () => {
    const edPriv = randomHex(32)
    const edPub = bytesToHex(ed25519.getPublicKey(hexToBytes(edPriv)))
    const kemPub = randomHex(32)
    const wrongKemPub = randomHex(32)

    const sig = signKemSig({ kemPub, edPriv })
    expect(verifyKemSig(edPub, wrongKemPub, sig)).toBe(false)
  })

  it("returns false for undefined sig", () => {
    expect(verifyKemSig("edPub", "kemPub", undefined)).toBe(false)
  })

  it("returns false for empty sig", () => {
    expect(verifyKemSig("edPub", "kemPub", "")).toBe(false)
  })

  it("returns false for malformed sig (does not throw)", () => {
    expect(verifyKemSig("edPub", "kemPub", "notvalid")).toBe(false)
  })
})
