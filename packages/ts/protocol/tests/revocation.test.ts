import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { ed25519 } from "@noble/curves/ed25519.js"
import { getBase64 } from "../src/platform.js"
import {
  buildRevocationList,
  revocationListCanonicalSigningInput,
  type RevocationList,
} from "../src/revocation.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/revocation-list.json")
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  issuer: { edPub: string; userId: string }
  generations: Record<string, { list: RevocationList; canonicalSigningInput: string }>
  forged: { list: RevocationList; canonicalSigningInput: string; expectVerify: boolean }
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16)
  return out
}

function edVerify(pubHex: string, sigB64: string, message: string): boolean {
  return ed25519.verify(getBase64().decode(sigB64), new TextEncoder().encode(message), hexToBytes(pubHex))
}

describe("revocation list canonical signing input", () => {
  it("matches the vector byte-for-byte (gen1 + gen2)", () => {
    for (const gen of ["1", "2"]) {
      const entry = vectors.generations[gen]!
      const { sig: _sig, ...unsigned } = entry.list
      expect(revocationListCanonicalSigningInput(unsigned)).toBe(entry.canonicalSigningInput)
    }
  })

  it("verifies the vector signatures and rejects the forged one", () => {
    const iss = vectors.issuer.edPub
    for (const gen of ["1", "2"]) {
      const entry = vectors.generations[gen]!
      expect(edVerify(iss, entry.list.sig, entry.canonicalSigningInput)).toBe(true)
    }
    expect(edVerify(iss, vectors.forged.list.sig, vectors.forged.canonicalSigningInput)).toBe(false)
  })
})

describe("buildRevocationList", () => {
  it("derives issUserId = sha256(edPub)[0:32] and self-verifies", () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const issEdPrivHex = Array.from(priv, (b) => b.toString(16).padStart(2, "0")).join("")
    const issEdPubHex = Array.from(pub, (b) => b.toString(16).padStart(2, "0")).join("")

    const revoked = [{ sub: "aa".repeat(32), nonce: getBase64().encode(new Uint8Array(16)), exp: 1999999999 }]
    const list = buildRevocationList({ issEdPubHex, issEdPrivHex, generation: 1, revoked })

    expect(list.v).toBe(1)
    expect(list.iss).toBe(issEdPubHex)
    expect(list.issUserId).toHaveLength(32) // 128-bit truncated hash
    expect(list.generation).toBe(1)
    expect(list.revoked).toEqual(revoked)
    expect(edVerify(issEdPubHex, list.sig, revocationListCanonicalSigningInput(list))).toBe(true)
  })

  it("includes revokedSubjects only when supplied", () => {
    const priv = ed25519.utils.randomSecretKey()
    const pub = ed25519.getPublicKey(priv)
    const issEdPrivHex = Array.from(priv, (b) => b.toString(16).padStart(2, "0")).join("")
    const issEdPubHex = Array.from(pub, (b) => b.toString(16).padStart(2, "0")).join("")

    const subjects = [{ sub: "bb".repeat(32), exp: 1999999999 }]
    const withSubjects = buildRevocationList({
      issEdPubHex,
      issEdPrivHex,
      generation: 3,
      revoked: [],
      revokedSubjects: subjects,
    })
    expect(withSubjects.revokedSubjects).toEqual(subjects)
    expect(edVerify(issEdPubHex, withSubjects.sig, revocationListCanonicalSigningInput(withSubjects))).toBe(true)

    const without = buildRevocationList({ issEdPubHex, issEdPrivHex, generation: 4, revoked: [] })
    expect(without.revokedSubjects).toBeUndefined()
  })
})
