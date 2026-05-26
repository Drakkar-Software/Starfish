import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  APPEND_AUTHOR_DOMAIN,
  appendAuthorCanonicalInput,
  signAppendAuthor,
  verifyAppendAuthor,
  verifyDocAuthor,
} from "../src/append-author.js"
import type { Alg } from "../src/suites/types.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/append-author.json")

interface VectorCase {
  label: string
  alg: Alg
  documentKey: string
  data: Record<string, unknown>
  canonicalSigningInput: string
  authorSignature: string
  expectVerify: boolean
}
interface Vector {
  signer: { label: string; edPriv: string; edPub: string }
  wrongSignerPub: { label: string; edPub: string }
  domain: string
  cases: VectorCase[]
}
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as Vector

describe("append-author cross-language vector", () => {
  it("domain tag matches the locked vector", () => {
    expect(APPEND_AUTHOR_DOMAIN).toBe(vectors.domain)
  })

  for (const c of vectors.cases) {
    it(`canonical input matches the vector for ${c.label}`, () => {
      expect(appendAuthorCanonicalInput(c.documentKey, c.data)).toBe(c.canonicalSigningInput)
    })

    it(`sign reproduces the locked signature for ${c.label} (deterministic ed25519)`, () => {
      const { authorPubkey, authorSignature } = signAppendAuthor(
        c.documentKey,
        c.data,
        vectors.signer.edPub,
        vectors.signer.edPriv,
        c.alg,
      )
      expect(authorPubkey).toBe(vectors.signer.edPub)
      expect(authorSignature).toBe(c.authorSignature)
    })

    it(`verifies the locked signature for ${c.label}`, () => {
      expect(
        verifyAppendAuthor(c.documentKey, c.data, vectors.signer.edPub, c.authorSignature, c.alg),
      ).toBe(c.expectVerify)
    })

    it(`rejects the wrong signer for ${c.label}`, () => {
      expect(
        verifyAppendAuthor(c.documentKey, c.data, vectors.wrongSignerPub.edPub, c.authorSignature, c.alg),
      ).toBe(false)
    })

    it(`rejects a different documentKey for ${c.label} (path binding)`, () => {
      expect(
        verifyAppendAuthor(`${c.documentKey}/elsewhere`, c.data, vectors.signer.edPub, c.authorSignature, c.alg),
      ).toBe(false)
    })
  }
})

describe("verifyAppendAuthor edge cases", () => {
  const c = vectors.cases[0] // simple-object
  const { edPub, edPriv } = vectors.signer

  it("rejects tampered data — the signature is over the exact bytes", () => {
    const tampered = { ...c.data, authorId: "evil" }
    expect(verifyAppendAuthor(c.documentKey, tampered, edPub, c.authorSignature, c.alg)).toBe(false)
  })

  it("returns false (never throws) on a malformed signature", () => {
    expect(verifyAppendAuthor(c.documentKey, c.data, edPub, "not valid base64 !!!", c.alg)).toBe(false)
  })

  it("returns false (never throws) on a malformed pubkey", () => {
    expect(verifyAppendAuthor(c.documentKey, c.data, "zz", c.authorSignature, c.alg)).toBe(false)
  })

  it("is independent of data key order (stableStringify canonicalisation)", () => {
    const reordered = { ts: 1747000000000, text: "hello", authorId: "abc" }
    const a = signAppendAuthor(c.documentKey, c.data, edPub, edPriv, c.alg)
    const b = signAppendAuthor(c.documentKey, reordered, edPub, edPriv, c.alg)
    expect(b.authorSignature).toBe(a.authorSignature)
  })

  it("an append-author signature does not verify as a doc-author signature (domain separation)", () => {
    const { authorSignature } = signAppendAuthor(c.documentKey, c.data, edPub, edPriv, c.alg)
    expect(verifyDocAuthor(c.documentKey, c.data, edPub, authorSignature, c.alg)).toBe(false)
  })
})
