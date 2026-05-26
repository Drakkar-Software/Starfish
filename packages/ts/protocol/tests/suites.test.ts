import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { getSuite, isAlg, suiteHasSeparateKem, DEFAULT_ALG } from "../src/suites/index.js"
import {
  assertCapCertWellFormed,
  recipientKem,
  signCapCert,
  userIdFromPubHex,
  verifyCapCert,
  verifyCapCertSignature,
  type UnsignedCapCert,
} from "../src/cap.js"
import { signRequest, verifyRequestSignature, type SignableRequest } from "../src/request-signing.js"
import { assertUsableSharedSecret, hexToBytes as decodeHex } from "../src/suites/_hex.js"

const __dirname = dirname(fileURLToPath(import.meta.url))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

interface SuiteCase {
  privHex: string
  pubHex: string
  messageUtf8: string
  signatureHex: string
  expectVerify: boolean
}
const secpVec = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../tests/test-vectors/suite-secp256k1.json"), "utf-8"),
) as { alg: "secp256k1-schnorr"; cases: SuiteCase[] }

interface EcdhCase {
  aPrivHex: string
  aPubHex: string
  aParity: "even" | "odd"
  bPrivHex: string
  bPubHex: string
  bParity: "even" | "odd"
  sharedHex: string
}
const ecdhVec = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../tests/test-vectors/suite-secp256k1-ecdh.json"), "utf-8"),
) as { alg: "secp256k1-schnorr"; cases: EcdhCase[] }

describe("crypto suite registry", () => {
  it("isAlg recognizes both suites and rejects junk", () => {
    expect(isAlg("ed25519")).toBe(true)
    expect(isAlg("secp256k1-schnorr")).toBe(true)
    expect(isAlg("rsa")).toBe(false)
    expect(isAlg(undefined)).toBe(false)
  })

  it("getSuite resolves implemented suites and throws fail-closed on unknown", () => {
    expect(getSuite("ed25519").alg).toBe("ed25519")
    expect(getSuite("secp256k1-schnorr").alg).toBe("secp256k1-schnorr")
    expect(getSuite(undefined).alg).toBe(DEFAULT_ALG)
    // @ts-expect-error — intentionally unknown alg
    expect(() => getSuite("rsa")).toThrow()
    // Empty string fails closed (only undefined defaults) — parity with Python.
    // @ts-expect-error — intentionally empty alg
    expect(() => getSuite("")).toThrow()
  })

  it("suiteHasSeparateKem: ed25519 yes, secp256k1 no", () => {
    expect(suiteHasSeparateKem("ed25519")).toBe(true)
    expect(suiteHasSeparateKem("secp256k1-schnorr")).toBe(false)
  })
})

describe("recipientKem — resolves the keyring recipient pubkey + suite", () => {
  it("ed25519 subject → separate X25519 subKem, kemAlg ed25519", () => {
    const r = recipientKem({ issAlg: "ed25519", subAlg: "ed25519", sub: "aa".repeat(32), subKem: "bb".repeat(32) })
    expect(r).toEqual({ kemPubHex: "bb".repeat(32), kemAlg: "ed25519" })
  })
  it("same-suite secp256k1 subject → sub IS the KEM key (no subKem)", () => {
    const r = recipientKem({ issAlg: "secp256k1-schnorr", subAlg: "secp256k1-schnorr", sub: "cc".repeat(32) })
    expect(r).toEqual({ kemPubHex: "cc".repeat(32), kemAlg: "secp256k1-schnorr" })
  })
  it("mixed: ed25519 sign + explicit secp256k1 subKemAlg → distinct subKem", () => {
    const r = recipientKem({ issAlg: "ed25519", subAlg: "ed25519", subKemAlg: "secp256k1-schnorr", sub: "aa".repeat(32), subKem: "dd".repeat(32) })
    expect(r).toEqual({ kemPubHex: "dd".repeat(32), kemAlg: "secp256k1-schnorr" })
  })
  it("kemAlg falls back through subAlg to issAlg", () => {
    expect(recipientKem({ issAlg: "secp256k1-schnorr", sub: "cc".repeat(32) }).kemAlg).toBe("secp256k1-schnorr")
  })
  it("throws for a subject-less (audience) cap", () => {
    expect(() => recipientKem({ issAlg: "ed25519" })).toThrow()
  })
})

describe("secp256k1 KEM (ECDH) cross-language conformance", () => {
  const suite = getSuite("secp256k1-schnorr")

  it("derives the vector's shared secret in both directions (byte-identical to coincurve)", () => {
    for (const c of ecdhVec.cases) {
      // Sanity: the suite re-derives the published x-only pubkeys from the privs.
      expect(suite.kemPublic(c.aPrivHex)).toBe(c.aPubHex)
      expect(suite.kemPublic(c.bPrivHex)).toBe(c.bPubHex)
      // ECDH both directions equal the vector's shared secret (parity-free + symmetric).
      expect(bytesToHex(suite.deriveSharedSecret(c.aPrivHex, c.bPubHex))).toBe(c.sharedHex)
      expect(bytesToHex(suite.deriveSharedSecret(c.bPrivHex, c.aPubHex))).toBe(c.sharedHex)
    }
  })

  it("exercises at least one odd-y peer (locks the even-y lift)", () => {
    const parities = ecdhVec.cases.flatMap((c) => [c.aParity, c.bParity])
    expect(parities).toContain("odd")
  })

  it("fails closed on a malformed peer pubkey (not a valid x-coordinate)", () => {
    // 0xFF…FF is ≥ p, so no curve point has it as an x — lift must throw, not
    // silently return a usable secret.
    expect(() => suite.deriveSharedSecret(ecdhVec.cases[0]!.aPrivHex, "ff".repeat(32))).toThrow()
  })

  it("fails closed on a low-order X25519 peer (no usable secret escapes)", () => {
    // An all-zero peer is a low-order point; deriveSharedSecret must reject it
    // (here @noble rejects at the curve layer — the contract is fail-closed,
    // whichever layer fires).
    const ed = getSuite("ed25519")
    expect(() => ed.deriveSharedSecret(ecdhVec.cases[0]!.aPrivHex, "00".repeat(32))).toThrow()
  })
})

describe("assertUsableSharedSecret — the degenerate-point backstop", () => {
  // Direct coverage of the guard so a refactor that drops it fails a test.
  // It is the PRIMARY defense for secp256k1 (a valid point never has an
  // all-zero x) and defense-in-depth for X25519 (RFC 7748 §6.1).
  it("throws on an all-zero shared secret", () => {
    expect(() => assertUsableSharedSecret(new Uint8Array(32))).toThrow(/zero KEM shared secret/)
  })

  it("accepts a non-zero shared secret (one non-zero byte is enough)", () => {
    const s = new Uint8Array(32)
    s[31] = 1
    expect(() => assertUsableSharedSecret(s)).not.toThrow()
  })
})

describe("verify fails closed (never throws)", () => {
  // CryptoSuite contract: `verify` NEVER throws — every decode/curve/length error
  // fails closed to false (secp256k1.py documents the DoS rationale). The vector
  // only exercises wrong-sig-with-valid-lengths (case 4); these hit the throw
  // paths. If verify threw here instead of returning false, the test fails.
  const m = new TextEncoder().encode("m")
  for (const alg of ["ed25519", "secp256k1-schnorr"] as const) {
    it(`${alg}: malformed sig/pubkey → false, not throw`, () => {
      const suite = getSuite(alg)
      expect(suite.verify(new Uint8Array(64), m, "abc")).toBe(false) // odd-length hex
      expect(suite.verify(new Uint8Array(64), m, "ab")).toBe(false) // wrong-length pubkey
      expect(suite.verify(new Uint8Array(64), m, "")).toBe(false) // empty pubkey
      expect(suite.verify(new Uint8Array(3), m, "aa".repeat(32))).toBe(false) // wrong-length sig
    })
  }
})

describe("subKem presence is suite-driven", () => {
  // ed25519 has a separate X25519 KEM key (subKem REQUIRED); secp256k1 reuses its
  // one key (subKem FORBIDDEN). The delegation canary covers only the positive
  // secp256k1-without-subKem path; these pin the two reject branches.
  function codeOf(fn: () => void): string {
    try {
      fn()
      return "NO_THROW"
    } catch (e) {
      return (e as Error & { code?: string }).code ?? (e as Error).message
    }
  }
  const iss = "aa".repeat(32)
  const sub = "bb".repeat(32)
  const base = {
    v: 1,
    kind: "member",
    iss,
    issUserId: userIdFromPubHex(iss),
    sub,
    subUserId: userIdFromPubHex(sub),
    scope: { ops: ["read"], collections: ["x"] },
    nbf: 1000,
    exp: 2000,
    nonce: Buffer.from(new Uint8Array(16).fill(1)).toString("base64"),
  }

  it("ed25519 (separate KEM): subKem required, absence is malformed", () => {
    const ed = { ...base, issAlg: "ed25519", subAlg: "ed25519" }
    expect(codeOf(() => assertCapCertWellFormed(ed as never))).toBe("malformed-shape")
    expect(codeOf(() => assertCapCertWellFormed({ ...ed, subKem: "cc".repeat(32) } as never))).toBe("NO_THROW")
  })

  it("secp256k1 (one key): subKem forbidden, presence is malformed", () => {
    const secp = { ...base, issAlg: "secp256k1-schnorr", subAlg: "secp256k1-schnorr" }
    expect(codeOf(() => assertCapCertWellFormed(secp as never))).toBe("NO_THROW")
    expect(codeOf(() => assertCapCertWellFormed({ ...secp, subKem: "cc".repeat(32) } as never))).toBe(
      "malformed-shape",
    )
  })
})

describe("secp256k1-schnorr suite — cross-language vector", () => {
  const suite = getSuite("secp256k1-schnorr")
  for (const [i, c] of secpVec.cases.entries()) {
    it(`case ${i}: verify === ${c.expectVerify}`, () => {
      const msg = new TextEncoder().encode(c.messageUtf8)
      expect(suite.verify(hexToBytes(c.signatureHex), msg, c.pubHex)).toBe(c.expectVerify)
    })
    if (c.expectVerify) {
      it(`case ${i}: re-sign reproduces the vector signature (deterministic)`, () => {
        const msg = new TextEncoder().encode(c.messageUtf8)
        expect(bytesToHex(suite.sign(msg, c.privHex))).toBe(c.signatureHex)
      })
    }
  }
})

describe("downgrade guard — alg is part of the signed bytes", () => {
  // Sign a request with one alg; flipping the declared alg on the signature
  // must fail verification (the canonical input embeds alg).
  it("request signature does not verify under a swapped alg", async () => {
    const priv = secpVec.cases[0]!.privHex
    const pub = secpVec.cases[0]!.pubHex
    const req: SignableRequest = { method: "GET", pathAndQuery: "/x", body: "" }
    const sig = await signRequest(req, priv, { alg: "secp256k1-schnorr" })
    expect(await verifyRequestSignature(req, sig, pub)).toBe(true)
    // Swap the declared alg → canonical input changes → verify fails.
    const swapped = { ...sig, alg: "ed25519" as const }
    expect(await verifyRequestSignature(req, swapped, pub)).toBe(false)
  })
})

describe("cross-suite delegation canary", () => {
  // An ed25519 issuer mints a member cap for a secp256k1 subject: the cap
  // signature verifies under issAlg=ed25519, and the subject's per-request
  // signature verifies under subAlg=secp256k1-schnorr.
  it("ed25519 issuer + secp256k1 subject: cap verifies and subject signs requests", async () => {
    // ed25519 issuer key (Alice's fixture root edPriv).
    const issPriv = "ad5a91be445615ad20823ff607df3d69f9fabc7a2f3f6cfce79dd6b8827e1a89"
    const issPub = bytesToHex(
      (await import("@noble/curves/ed25519.js")).ed25519.getPublicKey(hexToBytes(issPriv)),
    )
    const issUserId = bytesToHex(
      (await import("@noble/hashes/sha2.js")).sha256(hexToBytes(issPub)),
    ).slice(0, 32)
    // secp256k1 subject.
    const subCase = secpVec.cases[0]!
    const subUserId = bytesToHex(
      (await import("@noble/hashes/sha2.js")).sha256(hexToBytes(subCase.pubHex)),
    ).slice(0, 32)

    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "member",
      issAlg: "ed25519",
      subAlg: "secp256k1-schnorr",
      iss: issPub,
      issUserId,
      sub: subCase.pubHex,
      // No subKem — secp256k1 reuses one key (suiteHasSeparateKem === false).
      subUserId,
      scope: {
        ops: ["read"],
        collections: ["shared"],
        paths: ["shared/*", "!shared/_keyring", "!shared/_members"],
      },
      nbf: 1_747_000_000,
      exp: 1_747_000_000 + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(9)).toString("base64"),
    }
    const cert = signCapCert(unsigned, issPriv)
    // Cap-cert signature verifies under the issuer's suite.
    expect(verifyCapCertSignature(cert)).toBe(true)
    expect((await verifyCapCert(cert, { now: cert.nbf + 5 })).ok).toBe(true)

    // The subject signs a request with their own (secp256k1) suite.
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/shared", body: "" }
    const reqSig = await signRequest(req, subCase.privHex, { alg: cert.subAlg })
    expect(reqSig.alg).toBe("secp256k1-schnorr")
    expect(await verifyRequestSignature(req, reqSig, cert.sub!)).toBe(true)
  })

  it("subAlg absent ⇒ subject suite defaults to issAlg (tolerant-reader)", async () => {
    // A same-suite cap that omits subAlg on the wire. The subject signs under
    // issAlg (subAlg ?? issAlg) and that request signature must verify — guards
    // the client/server tolerant-reader fallback against a regression.
    const issPriv = secpVec.cases[0]!.privHex
    const issPub = secpVec.cases[0]!.pubHex
    const issUserId = bytesToHex(
      (await import("@noble/hashes/sha2.js")).sha256(hexToBytes(issPub)),
    ).slice(0, 32)
    const unsigned: UnsignedCapCert = {
      v: 1,
      kind: "device",
      issAlg: "secp256k1-schnorr",
      // subAlg intentionally omitted → defaults to issAlg.
      iss: issPub,
      issUserId,
      sub: issPub,
      scope: { ops: ["read"], collections: ["notes"], paths: ["notes/**"] },
      nbf: 1_747_000_000,
      exp: 1_747_000_000 + 3600,
      nonce: Buffer.from(new Uint8Array(16).fill(4)).toString("base64"),
    }
    const cert = signCapCert(unsigned, issPriv)
    expect((await verifyCapCert(cert, { now: cert.nbf + 5 })).ok).toBe(true)
    const reqAlg = cert.subAlg ?? cert.issAlg // resolver-equivalent resolution
    expect(reqAlg).toBe("secp256k1-schnorr")
    const req: SignableRequest = { method: "GET", pathAndQuery: "/pull/notes", body: "" }
    const reqSig = await signRequest(req, issPriv, { alg: reqAlg })
    expect(await verifyRequestSignature(req, reqSig, cert.sub!)).toBe(true)
  })
})

describe("subKemAlg — KEM suite decoupled from signing suite", () => {
  const ISS = "aa".repeat(32)
  function member(overrides: Record<string, unknown>): unknown {
    return {
      v: 1,
      kind: "member",
      issAlg: "ed25519",
      iss: ISS,
      issUserId: userIdFromPubHex(ISS),
      sub: "dd".repeat(32),
      subUserId: userIdFromPubHex("dd".repeat(32)),
      scope: { ops: ["read"], collections: ["x"], paths: ["x/*", "!x/_keyring", "!x/_members"] },
      nbf: 1000,
      exp: 2000,
      nonce: Buffer.from(new Uint8Array(16).fill(1)).toString("base64"),
      ...overrides,
    }
  }
  function code(fn: () => void): string {
    try {
      fn()
      return "OK"
    } catch (e) {
      return (e as Error & { code?: string }).code ?? (e as Error).message
    }
  }

  it("secp256k1 signing + ed25519/X25519 KEM: subKem (distinct key) required", () => {
    // subAlg=secp256k1 (no subKem normally), but subKemAlg=ed25519 forces a
    // separate X25519 KEM key → subKem MUST be present.
    expect(code(() =>
      assertCapCertWellFormed(
        member({ subAlg: "secp256k1-schnorr", subKemAlg: "ed25519", subKem: "ee".repeat(32) }) as never,
      ),
    )).toBe("OK")
    expect(code(() =>
      assertCapCertWellFormed(
        member({ subAlg: "secp256k1-schnorr", subKemAlg: "ed25519" }) as never, // subKem missing
      ),
    )).toBe("malformed-shape")
  })

  it("ed25519 signing + secp256k1 KEM: subKem (distinct key) required", () => {
    expect(code(() =>
      assertCapCertWellFormed(
        member({ subAlg: "ed25519", subKemAlg: "secp256k1-schnorr", subKem: "ff".repeat(32) }) as never,
      ),
    )).toBe("OK")
  })

  it("secp256k1 signing + secp256k1 KEM (same suite): subKem forbidden", () => {
    expect(code(() =>
      assertCapCertWellFormed(member({ subAlg: "secp256k1-schnorr" }) as never),
    )).toBe("OK")
    expect(code(() =>
      assertCapCertWellFormed(
        member({ subAlg: "secp256k1-schnorr", subKem: "ee".repeat(32) }) as never,
      ),
    )).toBe("malformed-shape")
  })

  it("audience cap must not carry subKemAlg", () => {
    const aud = {
      v: 1,
      kind: "audience",
      issAlg: "ed25519",
      iss: ISS,
      issUserId: userIdFromPubHex(ISS),
      subKemAlg: "ed25519",
      scope: { ops: ["read"], collections: ["b"], paths: ["b/**"] },
      nbf: 1000,
      exp: 2000,
      nonce: Buffer.from(new Uint8Array(16).fill(1)).toString("base64"),
    }
    expect(code(() => assertCapCertWellFormed(aud as never))).toBe("audience-has-sub")
  })

  it("rejects an unknown subKemAlg", () => {
    expect(code(() =>
      assertCapCertWellFormed(member({ subKemAlg: "rsa", subKem: "ee".repeat(32) }) as never),
    )).toBe("malformed-shape")
  })
})

describe("hexToBytes input validation", () => {
  it("decodes valid lowercase and uppercase hex", () => {
    expect([...decodeHex("00ff")]).toEqual([0, 255])
    expect([...decodeHex("DEadBE")]).toEqual([0xde, 0xad, 0xbe])
    expect([...decodeHex("")]).toEqual([])
  })

  it("throws on non-hex characters instead of silently zeroing (fail-closed, matches Python)", () => {
    // Before the fix `parseInt("zz",16)` → NaN → 0, so malformed hex became
    // zero bytes silently (and diverged from Python's `bytes.fromhex`).
    expect(() => decodeHex("zz")).toThrow(/invalid characters/)
    expect(() => decodeHex("0g")).toThrow(/invalid characters/)
    expect(() => decodeHex("0xff")).toThrow(/invalid characters/)
    expect(() => decodeHex("12cz")).toThrow(/invalid characters/)
  })

  it("throws on an odd-length string", () => {
    expect(() => decodeHex("abc")).toThrow(/odd length/)
  })
})
