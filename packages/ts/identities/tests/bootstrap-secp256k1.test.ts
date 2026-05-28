import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { sha256 } from "@noble/hashes/sha2.js"
import {
  SECP256K1_BOOTSTRAP_CHALLENGE,
  deriveRootIdentityFromSecp256k1Signature,
  deriveRootIdentity,
} from "../src/identity.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/identity-derivation-secp256k1.json")

interface Case {
  label: string
  secpPrivHex: string
  secpPubHex: string
  signatureHex: string
  edPrivHex: string
  edPubHex: string
  kemPrivHex: string
  kemPubHex: string
  userId: string
  bootstrapOrigin: { kind: "secp256k1"; pubHex: string }
}
interface Vector {
  challenge: { literal: string; challengeHex: string }
  hkdf: { saltUtf8: string; signInfoUtf8: string; kemInfoUtf8: string }
  cases: Case[]
}

const vector = JSON.parse(readFileSync(vectorPath, "utf-8")) as Vector

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

describe("SECP256K1_BOOTSTRAP_CHALLENGE", () => {
  it("equals sha256 of the literal challenge string", () => {
    const expected = sha256(new TextEncoder().encode(vector.challenge.literal))
    expect(bytesToHex(expected)).toBe(vector.challenge.challengeHex)
    expect(bytesToHex(SECP256K1_BOOTSTRAP_CHALLENGE)).toBe(vector.challenge.challengeHex)
  })

  it("is exactly 32 bytes (the BIP-340 message length)", () => {
    expect(SECP256K1_BOOTSTRAP_CHALLENGE.length).toBe(32)
  })
})

describe("deriveRootIdentityFromSecp256k1Signature — locked vector cases", () => {
  for (const c of vector.cases) {
    it(`${c.label}: derives the expected Ed25519 + X25519 seeds + userId`, async () => {
      const identity = await deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: c.secpPubHex,
        signature: hexToBytes(c.signatureHex),
      })
      expect(identity.keys.edPriv).toBe(c.edPrivHex)
      expect(identity.keys.edPub).toBe(c.edPubHex)
      expect(identity.keys.kemPriv).toBe(c.kemPrivHex)
      expect(identity.keys.kemPub).toBe(c.kemPubHex)
      expect(identity.userId).toBe(c.userId)
      expect(identity.bootstrapOrigin).toEqual(c.bootstrapOrigin)
    })
  }
})

describe("deriveRootIdentityFromSecp256k1Signature — determinism", () => {
  it("same input twice yields identical keys + userId", async () => {
    const c = vector.cases[0]!
    const a = await deriveRootIdentityFromSecp256k1Signature({
      secpPubHex: c.secpPubHex,
      signature: hexToBytes(c.signatureHex),
    })
    const b = await deriveRootIdentityFromSecp256k1Signature({
      secpPubHex: c.secpPubHex,
      signature: hexToBytes(c.signatureHex),
    })
    expect(a.userId).toBe(b.userId)
    expect(a.keys).toEqual(b.keys)
  })
})

describe("deriveRootIdentityFromSecp256k1Signature — fail-closed validation", () => {
  const good = vector.cases[0]!

  it("rejects a 63-byte signature", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex,
        signature: hexToBytes(good.signatureHex).slice(0, 63),
      }),
    ).rejects.toThrow(/64-byte/)
  })

  it("rejects a 65-byte signature", async () => {
    const sig = new Uint8Array(65)
    sig.set(hexToBytes(good.signatureHex))
    await expect(
      deriveRootIdentityFromSecp256k1Signature({ secpPubHex: good.secpPubHex, signature: sig }),
    ).rejects.toThrow(/64-byte/)
  })

  it("rejects a forged 64-byte all-zero signature against a valid pubkey", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex,
        signature: new Uint8Array(64),
      }),
    ).rejects.toThrow(/does not verify/)
  })

  it("rejects a non-hex secpPubHex", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: "zz".repeat(32),
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/64 lowercase hex/)
  })

  it("rejects a 63-char secpPubHex", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex.slice(0, 63),
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/64 lowercase hex/)
  })

  it("rejects a 65-char secpPubHex", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex + "a",
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/64 lowercase hex/)
  })

  it("rejects an uppercase secpPubHex (lowercase-only contract)", async () => {
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex.toUpperCase(),
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/64 lowercase hex/)
  })

  it("rejects a secpPubHex with a trailing newline (cross-lang lockstep)", async () => {
    // Python's regex `$` matches before a final `\n`, so a trailing newline
    // would slip past `match()` there. TS uses `/^[0-9a-f]{64}$/.test`, which
    // already rejects it. This test pins the symmetric Python behavior.
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: good.secpPubHex + "\n",
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/64 lowercase hex/)
  })

  it("rejects a valid signature paired with the WRONG secpPubHex (binding check)", async () => {
    const other = vector.cases[1]!
    await expect(
      deriveRootIdentityFromSecp256k1Signature({
        secpPubHex: other.secpPubHex,
        signature: hexToBytes(good.signatureHex),
      }),
    ).rejects.toThrow(/does not verify/)
  })
})

describe("bootstrapOrigin metadata", () => {
  it("is set to the originating secp256k1 pubkey for bootstrapped identities", async () => {
    const c = vector.cases[0]!
    const id = await deriveRootIdentityFromSecp256k1Signature({
      secpPubHex: c.secpPubHex,
      signature: hexToBytes(c.signatureHex),
    })
    expect(id.bootstrapOrigin).toEqual({ kind: "secp256k1", pubHex: c.secpPubHex })
  })

  it("is undefined for passphrase-derived identities", async () => {
    const id = await deriveRootIdentity("alice-root-passphrase")
    expect(id.bootstrapOrigin).toBeUndefined()
  })
})
