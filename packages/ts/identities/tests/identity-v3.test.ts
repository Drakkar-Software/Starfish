import { describe, it, expect } from "vitest"
import { deriveRootIdentity } from "../src/identity.js"
import { bootstrapRootIdentity } from "../src/pairing.js"
import vectors from "../../../../tests/test-vectors/identity-derivation.json"

interface IdentityVector {
  passphrase: string
  rootEdPriv: string
  rootEdPub: string
  rootKemPriv: string
  rootKemPub: string
  userId: string
}

const ENTRIES = (vectors as { vectors: IdentityVector[] }).vectors

describe("deriveRootIdentity — cross-language vectors", () => {
  for (const v of ENTRIES) {
    it(`matches vector for passphrase ${JSON.stringify(v.passphrase)}`, async () => {
      const result = await deriveRootIdentity(v.passphrase)
      expect(result.keys.edPriv).toBe(v.rootEdPriv)
      expect(result.keys.edPub).toBe(v.rootEdPub)
      expect(result.keys.kemPriv).toBe(v.rootKemPriv)
      expect(result.keys.kemPub).toBe(v.rootKemPub)
      expect(result.userId).toBe(v.userId)
    })
  }
})

describe("deriveRootIdentity — shape", () => {
  it("returns 64-char lowercase hex strings for all keys", async () => {
    const result = await deriveRootIdentity("hello world")
    const hex64 = /^[0-9a-f]{64}$/
    expect(result.keys.edPriv).toMatch(hex64)
    expect(result.keys.edPub).toMatch(hex64)
    expect(result.keys.kemPriv).toMatch(hex64)
    expect(result.keys.kemPub).toMatch(hex64)
    expect(result.userId).toMatch(/^[0-9a-f]{32}$/)  // userId = sha256(edPub)[:32] (128-bit)
  })

  it("is deterministic — same passphrase yields same identity", async () => {
    const a = await deriveRootIdentity("a passphrase")
    const b = await deriveRootIdentity("a passphrase")
    expect(a).toEqual(b)
  })

  it("different passphrases yield different identities", async () => {
    const a = await deriveRootIdentity("passphrase one")
    const b = await deriveRootIdentity("passphrase two")
    expect(a.keys.edPriv).not.toBe(b.keys.edPriv)
    expect(a.keys.kemPriv).not.toBe(b.keys.kemPriv)
    expect(a.userId).not.toBe(b.userId)
  })

  it("NFC-normalizes: precomposed and decomposed spellings derive one identity", async () => {
    // Same passphrase spelled two ways: precomposed "é" (U+00E9) vs decomposed
    // "e" + combining acute accent (U+0065 U+0301). Without NFC these derive two
    // different root identities → silent cross-device lockout.
    const precomposed = "café-passphrase"
    const decomposed = "café-passphrase"
    expect(precomposed).not.toBe(decomposed)
    const a = await deriveRootIdentity(precomposed)
    const b = await deriveRootIdentity(decomposed)
    expect(a.keys.edPub).toBe(b.keys.edPub)
    expect(a.userId).toBe(b.userId)
    expect(a).toEqual(b)
  })
})

describe("deriveRootIdentity / bootstrapRootIdentity — empty passphrase rejection", () => {
  it("deriveRootIdentity('') throws", async () => {
    await expect(deriveRootIdentity("")).rejects.toThrow()
  })

  it("deriveRootIdentity whitespace-only throws", async () => {
    await expect(deriveRootIdentity("   ")).rejects.toThrow()
  })

  it("bootstrapRootIdentity('') throws", async () => {
    await expect(bootstrapRootIdentity("")).rejects.toThrow()
  })
})
