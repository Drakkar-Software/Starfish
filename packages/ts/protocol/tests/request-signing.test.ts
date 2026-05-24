import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  requestSigningCanonicalInput,
  signRequest,
  verifyRequestSignature,
  isWithinClockSkew,
  type SignableMethod,
  type SignableRequest,
} from "../src/request-signing.js"
import type { Alg } from "../src/suites/types.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(
  __dirname,
  "../../../../tests/test-vectors/request-signature.json",
)

interface VectorCase {
  label: string
  alg: Alg
  method: SignableMethod
  pathAndQuery: string
  bodyUtf8: string
  host?: string
  verifyHost?: string
  tsMs: number
  nonceBase64: string
  canonicalSigningInput: string
  signatureBase64: string
  expectVerify: boolean
  verifyPubkey?: string
}

interface Vector {
  signer: { label: string; edPub: string }
  wrongSignerPub: { label: string; edPub: string }
  cases: VectorCase[]
}

const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as Vector

// ─── Replicate the test-vector generator's device-key chain inline ──────────
// HKDF(IKM=utf8("alice-root-passphrase::alice-laptop"),
//      salt=utf8("starfish-device-sign-test-vector"),
//      info=utf8("ed25519"),
//      len=32)
// is alice_dev_1's Ed25519 32-byte seed / private key.
async function deriveAliceDev1EdPrivHex(): Promise<string> {
  const enc = new TextEncoder()
  const ikm = enc.encode("alice-root-passphrase::alice-laptop")
  const salt = enc.encode("starfish-device-sign-test-vector")
  const info = enc.encode("ed25519")
  const subtle = (globalThis.crypto as Crypto).subtle
  const keyMaterial = await subtle.importKey(
    "raw",
    ikm as BufferSource,
    "HKDF",
    false,
    ["deriveBits"],
  )
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    keyMaterial,
    32 * 8,
  )
  return Array.from(new Uint8Array(bits), (b) => b.toString(16).padStart(2, "0")).join("")
}

function base64DecodeStandard(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
}

describe("requestSigningCanonicalInput", () => {
  for (const c of vectors.cases) {
    it(`matches vector canonical input for ${c.label}`, () => {
      const req: SignableRequest = {
        method: c.method,
        pathAndQuery: c.pathAndQuery,
        body: c.bodyUtf8,
        host: c.host,
      }
      const canon = requestSigningCanonicalInput(req, c.tsMs, c.nonceBase64, c.alg)
      expect(canon).toBe(c.canonicalSigningInput)
    })
  }

  it("handles undefined body as empty (SHA-256 of empty buffer)", () => {
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/x",
    }
    const canon = requestSigningCanonicalInput(req, 0, "AA==", "ed25519")
    expect(canon).toContain(
      '"b":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
    )
  })

  it("emits h:\"\" when host is omitted", () => {
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/x",
    }
    const canon = requestSigningCanonicalInput(req, 0, "AA==", "ed25519")
    expect(canon).toContain('"h":""')
  })

  it("emits h:<host> when host is provided", () => {
    const req: SignableRequest = {
      method: "GET",
      pathAndQuery: "/x",
      host: "api.example.com",
    }
    const canon = requestSigningCanonicalInput(req, 0, "AA==", "ed25519")
    expect(canon).toContain('"h":"api.example.com"')
  })
})

describe("verifyRequestSignature", () => {
  it("verifies pull-empty-body against alice_dev_1.edPub", async () => {
    const c = vectors.cases.find((x) => x.label === "pull-empty-body")!
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const ok = await verifyRequestSignature(
      req,
      { alg: c.alg, sig: c.signatureBase64, ts: c.tsMs, nonce: c.nonceBase64 },
      vectors.signer.edPub,
    )
    expect(ok).toBe(true)
  })

  it("verifies push-json-body against alice_dev_1.edPub", async () => {
    const c = vectors.cases.find((x) => x.label === "push-json-body")!
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const ok = await verifyRequestSignature(
      req,
      { alg: c.alg, sig: c.signatureBase64, ts: c.tsMs, nonce: c.nonceBase64 },
      vectors.signer.edPub,
    )
    expect(ok).toBe(true)
  })

  it("rejects wrong-signer (bob signed, verified against alice)", async () => {
    const c = vectors.cases.find((x) => x.label === "wrong-signer")!
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const ok = await verifyRequestSignature(
      req,
      { alg: c.alg, sig: c.signatureBase64, ts: c.tsMs, nonce: c.nonceBase64 },
      vectors.signer.edPub,
    )
    expect(ok).toBe(false)
  })

  it("rejects host-mismatch (signed with host A, verified with host B)", async () => {
    const c = vectors.cases.find((x) => x.label === "host-mismatch")!
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.verifyHost,
    }
    const ok = await verifyRequestSignature(
      req,
      { alg: c.alg, sig: c.signatureBase64, ts: c.tsMs, nonce: c.nonceBase64 },
      vectors.signer.edPub,
    )
    expect(ok).toBe(false)
  })

  it("host-mismatch case verifies OK when canonical is rebuilt with the signed host", async () => {
    const c = vectors.cases.find((x) => x.label === "host-mismatch")!
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const ok = await verifyRequestSignature(
      req,
      { alg: c.alg, sig: c.signatureBase64, ts: c.tsMs, nonce: c.nonceBase64 },
      vectors.signer.edPub,
    )
    expect(ok).toBe(true)
  })
})

describe("signRequest roundtrip", () => {
  it("produces vector signature for pull-empty-body", async () => {
    const c = vectors.cases.find((x) => x.label === "pull-empty-body")!
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const sig = await signRequest(req, devEdPrivHex, {
      ts: c.tsMs,
      nonce: base64DecodeStandard(c.nonceBase64),
    })
    expect(sig.ts).toBe(c.tsMs)
    expect(sig.nonce).toBe(c.nonceBase64)
    expect(sig.sig).toBe(c.signatureBase64)
  })

  it("produces vector signature for push-json-body", async () => {
    const c = vectors.cases.find((x) => x.label === "push-json-body")!
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = {
      method: c.method,
      pathAndQuery: c.pathAndQuery,
      body: c.bodyUtf8,
      host: c.host,
    }
    const sig = await signRequest(req, devEdPrivHex, {
      ts: c.tsMs,
      nonce: base64DecodeStandard(c.nonceBase64),
    })
    expect(sig.ts).toBe(c.tsMs)
    expect(sig.nonce).toBe(c.nonceBase64)
    expect(sig.sig).toBe(c.signatureBase64)
  })

  it("default ts and nonce produce a verifiable signature", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    // Need the matching pub key. Derive once via @noble/curves used inside lib;
    // here just sign and verify with the public key from the vector.
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
    }
    const sig = await signRequest(req, devEdPrivHex)
    expect(sig.ts).toBeGreaterThan(0)
    expect(typeof sig.nonce).toBe("string")
    expect(typeof sig.sig).toBe("string")
    const ok = await verifyRequestSignature(req, sig, vectors.signer.edPub)
    expect(ok).toBe(true)
  })
})

describe("verifyRequestSignature — tampered fields", () => {
  it("rejects when ts is bumped after signing", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = { method: "POST", pathAndQuery: "/x", body: "hello" }
    const ts = 1_700_000_000_000
    const nonce = base64DecodeStandard("AAECAwQFBgcICQoLDA0ODw==")
    const sig = await signRequest(req, devEdPrivHex, { ts, nonce })
    // Re-derive canonical with ts+1 → signature won't match.
    const tampered = { ...sig, ts: ts + 1 }
    const ok = await verifyRequestSignature(req, tampered, vectors.signer.edPub)
    expect(ok).toBe(false)
  })

  it("rejects when nonce is changed after signing", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = { method: "POST", pathAndQuery: "/x", body: "hello" }
    const ts = 1_700_000_000_000
    const nonce = base64DecodeStandard("AAECAwQFBgcICQoLDA0ODw==")
    const sig = await signRequest(req, devEdPrivHex, { ts, nonce })
    // A different nonce, same length.
    const tamperedNonceB64 = "EBESExQVFhcYGRobHB0eHw=="
    const tampered = { ...sig, nonce: tamperedNonceB64 }
    const ok = await verifyRequestSignature(req, tampered, vectors.signer.edPub)
    expect(ok).toBe(false)
  })

  it("rejects a re-encoded but byte-equivalent nonce", async () => {
    // The nonce is bound as the verbatim base64 STRING, not as decoded bytes: a
    // padded and an unpadded base64 of the SAME 16 bytes decode identically, but the
    // canonical input embeds the string verbatim, so swapping encodings fails verify.
    // This keeps the string-keyed nonce cache safe — re-encoding a captured nonce
    // onto a different cache key invalidates the signature (the sibling test above
    // only changes the nonce to *different* bytes).
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = { method: "POST", pathAndQuery: "/x", body: "hello" }
    const ts = 1_700_000_000_000
    const nonce = base64DecodeStandard("AAECAwQFBgcICQoLDA0ODw==")
    const sig = await signRequest(req, devEdPrivHex, { ts, nonce })
    expect(sig.nonce.endsWith("==")).toBe(true)
    const unpadded = sig.nonce.replace(/=+$/, "") // same bytes, different string
    expect(base64DecodeStandard(unpadded + "==")).toEqual(nonce)
    const tampered = { ...sig, nonce: unpadded }
    const ok = await verifyRequestSignature(req, tampered, vectors.signer.edPub)
    expect(ok).toBe(false)
  })

  it("rejects when the body is tampered (single byte flipped, same length)", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const ts = 1_700_000_000_000
    const nonce = base64DecodeStandard("AAECAwQFBgcICQoLDA0ODw==")
    const req: SignableRequest = { method: "POST", pathAndQuery: "/x", body: "hello" }
    const sig = await signRequest(req, devEdPrivHex, { ts, nonce })
    // Same length, last byte changed.
    const tamperedReq: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hellp",
    }
    expect(tamperedReq.body!.length).toBe(req.body!.length)
    const ok = await verifyRequestSignature(tamperedReq, sig, vectors.signer.edPub)
    expect(ok).toBe(false)
  })
})

describe("host binding", () => {
  it("sign+verify both pass when host matches", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
      host: "api.example.com",
    }
    const sig = await signRequest(req, devEdPrivHex)
    const ok = await verifyRequestSignature(req, sig, vectors.signer.edPub)
    expect(ok).toBe(true)
  })

  it("verify fails when host differs between sign and verify", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const signed: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
      host: "api.example.com",
    }
    const sig = await signRequest(signed, devEdPrivHex)
    const tampered: SignableRequest = {
      ...signed,
      host: "evil.example.com",
    }
    const ok = await verifyRequestSignature(tampered, sig, vectors.signer.edPub)
    expect(ok).toBe(false)
  })

  it("sign+verify both pass when host is omitted on both sides", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
    }
    const sig = await signRequest(req, devEdPrivHex)
    const ok = await verifyRequestSignature(req, sig, vectors.signer.edPub)
    expect(ok).toBe(true)
  })

  it("verify fails when sign omits host but verify provides one", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const signed: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
    }
    const sig = await signRequest(signed, devEdPrivHex)
    const onWire: SignableRequest = { ...signed, host: "api.example.com" }
    const ok = await verifyRequestSignature(onWire, sig, vectors.signer.edPub)
    expect(ok).toBe(false)
  })

  it("verify fails when sign provides host but verify omits it", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const signed: SignableRequest = {
      method: "POST",
      pathAndQuery: "/x",
      body: "hello",
      host: "api.example.com",
    }
    const sig = await signRequest(signed, devEdPrivHex)
    const onWire: SignableRequest = {
      method: signed.method,
      pathAndQuery: signed.pathAndQuery,
      body: signed.body,
    }
    const ok = await verifyRequestSignature(onWire, sig, vectors.signer.edPub)
    expect(ok).toBe(false)
  })
})

describe("PATCH support", () => {
  it("signs and verifies a PATCH request end-to-end", async () => {
    const devEdPrivHex = await deriveAliceDev1EdPrivHex()
    const req: SignableRequest = {
      method: "PATCH",
      pathAndQuery: "/x",
      body: "",
    }
    const sig = await signRequest(req, devEdPrivHex)
    expect(typeof sig.sig).toBe("string")
    const ok = await verifyRequestSignature(req, sig, vectors.signer.edPub)
    expect(ok).toBe(true)
  })
})

describe("isWithinClockSkew", () => {
  const now = 1_700_000_000_000
  it("returns true when within default 5-minute skew", () => {
    expect(isWithinClockSkew(now + 200_000, now)).toBe(true)
    expect(isWithinClockSkew(now - 200_000, now)).toBe(true)
  })
  it("returns false when outside default 5-minute skew", () => {
    expect(isWithinClockSkew(now + 600_000, now)).toBe(false)
    expect(isWithinClockSkew(now - 600_000, now)).toBe(false)
  })
  it("respects custom maxSkewMs", () => {
    expect(isWithinClockSkew(now + 1_000, now, 500)).toBe(false)
    expect(isWithinClockSkew(now + 200, now, 500)).toBe(true)
  })
  it("is inclusive at exactly ±maxSkewMs and excludes one ms beyond (strict <= boundary)", () => {
    // The gate is `|reqTs - nowMs| <= maxSkewMs`, so a ts exactly maxSkew away is
    // accepted and one ms further is rejected. Pinned both sides so an off-by-one
    // (`<` vs `<=`) can't slip in. Mirrors test_request_signing.py.
    expect(isWithinClockSkew(now + 300_000, now)).toBe(true)
    expect(isWithinClockSkew(now - 300_000, now)).toBe(true)
    expect(isWithinClockSkew(now + 300_001, now)).toBe(false)
    expect(isWithinClockSkew(now - 300_001, now)).toBe(false)
  })
})
