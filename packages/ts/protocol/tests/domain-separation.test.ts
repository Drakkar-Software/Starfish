import { describe, it, expect } from "vitest"
import { ed25519 } from "@noble/curves/ed25519.js"
import { capCertCanonicalSigningInput } from "../src/cap.js"
import { requestSigningCanonicalInput, type SignableRequest } from "../src/request-signing.js"
import { revocationListCanonicalSigningInput } from "../src/revocation.js"
import { appendAuthorCanonicalInput } from "../src/append-author.js"
import * as ed25519Suite from "../src/suites/ed25519.js"

// Cross-type signature domain separation (mirrors test_domain_separation.py).
//
// Each of the four signature types — cap-cert, per-request, revocation-list and
// append-author — prepends a distinct domain tag to its canonical signing
// input. This binds a signature to its message type BY CONSTRUCTION: even if a
// future field change made two of the stable-stringified bodies byte-identical,
// a signature minted for one type can never verify as another, because the
// signed bytes carry different domain tags.

const enc = (s: string) => new TextEncoder().encode(s)

function edKeypair(): { privHex: string; pubHex: string } {
  const priv = ed25519.utils.randomSecretKey()
  const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
  return { privHex: toHex(priv), pubHex: toHex(ed25519.getPublicKey(priv)) }
}

describe("signature domain separation across message types", () => {
  const req: SignableRequest = {
    method: "GET",
    pathAndQuery: "/pull/notes/x/0",
    host: "api.example.com",
  }
  const capCanon = capCertCanonicalSigningInput({
    v: 1,
    kind: "device",
    iss: "aa".repeat(32),
    issUserId: "x",
    scope: { ops: ["read"], collections: ["c"] },
    nbf: 0,
    exp: 1,
    nonce: "AAAAAAAAAAAAAAAAAAAAAA==",
  } as never)
  const reqCanon = requestSigningCanonicalInput(req, 1, "AAAAAAAAAAAAAAAAAAAAAA==")
  const revCanon = revocationListCanonicalSigningInput({
    v: 1,
    iss: "aa".repeat(32),
    issUserId: "x",
    generation: 1,
  } as never)
  const apdCanon = appendAuthorCanonicalInput("events", { msg: "hello" })

  it("each canonical input starts with its own distinct domain tag", () => {
    expect(capCanon.startsWith("starfish-capcert-v1\n")).toBe(true)
    expect(reqCanon.startsWith("starfish-req-v1\n")).toBe(true)
    expect(revCanon.startsWith("starfish-revlist-v1\n")).toBe(true)
    expect(apdCanon.startsWith("starfish-append-author-v1\n")).toBe(true)
    // Distinct from one another.
    expect(
      new Set([capCanon, reqCanon, revCanon, apdCanon].map((s) => s.split("\n")[0])).size,
    ).toBe(4)
  })

  it("a cap-cert signature does not verify as request / revocation / append-author", () => {
    const { privHex, pubHex } = edKeypair()
    const sig = ed25519Suite.sign(enc(capCanon), privHex)
    expect(ed25519Suite.verify(sig, enc(capCanon), pubHex)).toBe(true)
    expect(ed25519Suite.verify(sig, enc(reqCanon), pubHex)).toBe(false)
    expect(ed25519Suite.verify(sig, enc(revCanon), pubHex)).toBe(false)
    expect(ed25519Suite.verify(sig, enc(apdCanon), pubHex)).toBe(false)
  })

  it("an append-author signature does not verify as a cap-cert / request signature", () => {
    const { privHex, pubHex } = edKeypair()
    const sig = ed25519Suite.sign(enc(apdCanon), privHex)
    expect(ed25519Suite.verify(sig, enc(apdCanon), pubHex)).toBe(true)
    expect(ed25519Suite.verify(sig, enc(capCanon), pubHex)).toBe(false)
    expect(ed25519Suite.verify(sig, enc(reqCanon), pubHex)).toBe(false)
  })
})
