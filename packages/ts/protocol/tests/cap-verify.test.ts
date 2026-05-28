import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  signCapCert,
  verifyCapCertSignature,
  verifyCapCert,
  assertCapCertWellFormed,
  pathGlobMatch,
  type CapCert,
  type UnsignedCapCert,
} from "../src/cap.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(
  __dirname,
  "../../../../tests/test-vectors/cap-cert.json",
)
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  deviceCap: { cert: CapCert; canonicalSigningInput: string; signatureBase64: string }
  memberCap: { cert: CapCert; canonicalSigningInput: string; signatureBase64: string }
  forgedDeviceCap: { cert: CapCert; canonicalSigningInput: string }
}

// Alice's root edPriv — deriveRootIdentity("alice-root-passphrase").keys.edPriv.
const ALICE_ED_PRIV = "ad5a91be445615ad20823ff607df3d69f9fabc7a2f3f6cfce79dd6b8827e1a89"

describe("verifyCapCertSignature", () => {
  it("verifies the deviceCap vector", async () => {
    const ok = await verifyCapCertSignature(vectors.deviceCap.cert)
    expect(ok).toBe(true)
  })

  it("verifies the memberCap vector", async () => {
    const ok = await verifyCapCertSignature(vectors.memberCap.cert)
    expect(ok).toBe(true)
  })

  it("rejects the forgedDeviceCap vector", async () => {
    const ok = await verifyCapCertSignature(vectors.forgedDeviceCap.cert)
    expect(ok).toBe(false)
  })
})

describe("verifyCapCert", () => {
  it("returns ok=true for a valid device cap inside its validity window", async () => {
    const cert = vectors.deviceCap.cert
    const result = await verifyCapCert(cert, { now: cert.nbf + 100 })
    expect(result.ok).toBe(true)
  })

  it("returns ok=true for a valid member cap inside its validity window", async () => {
    // The pinned vector pre-dates the `member-keyring-not-denied` and
    // `member-members-not-denied` rules; patch the cert in-memory and re-sign
    // so the orchestrator passes every check end-to-end.
    const base = vectors.memberCap.cert
    const unsigned: UnsignedCapCert = {
      v: base.v,
      kind: base.kind,
      iss: base.iss,
      issUserId: base.issUserId,
      sub: base.sub,
      subKem: base.subKem,
      subUserId: base.subUserId,
      scope: {
        ops: [...base.scope.ops],
        collections: [...base.scope.collections],
        paths: ["shared-notes/*", "!shared-notes/_keyring", "!shared-notes/_members"],
      },
      nbf: base.nbf,
      exp: base.exp,
      nonce: base.nonce,
    }
    const cert = await signCapCert(unsigned, ALICE_ED_PRIV)
    const result = await verifyCapCert(cert, { now: cert.nbf + 100 })
    expect(result.ok).toBe(true)
  })

  it("returns ok=false for the forged device cap", async () => {
    const cert = vectors.forgedDeviceCap.cert
    const result = await verifyCapCert(cert, { now: cert.nbf + 100 })
    expect(result.ok).toBe(false)
  })

  it("returns ok=false when now < nbf - skew", async () => {
    const cert = vectors.deviceCap.cert
    const result = await verifyCapCert(cert, { now: cert.nbf - 1000, clockSkewSec: 0 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBeDefined()
  })

  it("returns ok=false when now > exp + skew", async () => {
    const cert = vectors.deviceCap.cert
    const result = await verifyCapCert(cert, { now: cert.exp + 1000, clockSkewSec: 0 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBeDefined()
  })

  it("honors clockSkewSec", async () => {
    const cert = vectors.deviceCap.cert
    const result = await verifyCapCert(cert, { now: cert.nbf - 60 })
    expect(result.ok).toBe(true)
  })

  it("treats the exact expiry+skew instant as still valid and one second past as expired", async () => {
    const cert = vectors.deviceCap.cert
    const skew = 300
    expect((await verifyCapCert(cert, { now: cert.exp + skew, clockSkewSec: skew })).ok).toBe(true)
    const past = await verifyCapCert(cert, { now: cert.exp + skew + 1, clockSkewSec: skew })
    expect(past.ok).toBe(false)
    expect(past.reason).toBe("expired")
  })

  it("treats the exact nbf-skew instant as already valid and one second earlier as not-yet-valid", async () => {
    const cert = vectors.deviceCap.cert
    const skew = 300
    expect((await verifyCapCert(cert, { now: cert.nbf - skew, clockSkewSec: skew })).ok).toBe(true)
    const before = await verifyCapCert(cert, { now: cert.nbf - skew - 1, clockSkewSec: skew })
    expect(before.ok).toBe(false)
    expect(before.reason).toBe("not-yet-valid")
  })

  it("accepts an empty ops list as well-formed (authorizes nothing, not a wildcard)", async () => {
    const base = vectors.deviceCap.cert
    const unsigned = { ...base, scope: { ...base.scope, ops: [] } } as Record<string, unknown>
    delete unsigned["sig"]
    const signed = await signCapCert(unsigned as unknown as UnsignedCapCert, ALICE_ED_PRIV)
    expect(() => assertCapCertWellFormed(signed)).not.toThrow()
    const result = await verifyCapCert(signed, { now: base.nbf + 100 })
    expect(result.ok).toBe(true)
    expect(signed.scope.ops).toEqual([])
  })

  it("rejects an inverted validity window (exp before nbf) with reason inverted-window", async () => {
    const base = vectors.deviceCap.cert
    const unsigned = { ...base, exp: base.nbf - 100 } as Record<string, unknown>
    delete unsigned["sig"]
    const signed = await signCapCert(unsigned as unknown as UnsignedCapCert, ALICE_ED_PRIV)
    const result = await verifyCapCert(signed, { now: base.nbf, clockSkewSec: 300 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe("inverted-window")
  })

  it("rejects a zero-width validity window (exp === nbf)", async () => {
    const base = vectors.deviceCap.cert
    const unsigned = { ...base, exp: base.nbf } as Record<string, unknown>
    delete unsigned["sig"]
    const signed = await signCapCert(unsigned as unknown as UnsignedCapCert, ALICE_ED_PRIV)
    const result = await verifyCapCert(signed, { now: base.nbf, clockSkewSec: 300 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe("inverted-window")
  })

  it("rejects a validly-signed cert whose scope.ops is a string (no junk-role synthesis)", async () => {
    const base = vectors.deviceCap.cert
    const malformed = {
      v: base.v,
      kind: base.kind,
      iss: base.iss,
      issUserId: base.issUserId,
      sub: base.sub,
      subKem: base.subKem,
      scope: { ops: "read", collections: ["notes"] },
      nbf: base.nbf,
      exp: base.exp,
      nonce: base.nonce,
    }
    const signed = await signCapCert(malformed as unknown as UnsignedCapCert, ALICE_ED_PRIV)
    expect(await verifyCapCertSignature(signed)).toBe(true)
    const result = await verifyCapCert(signed, { now: base.nbf + 100 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe("malformed-shape")
  })
})

describe("signCapCert", () => {
  it("produces the vector signature when re-signing the deviceCap canonical input with alice's edPriv", async () => {
    const cert = vectors.deviceCap.cert
    const unsigned: UnsignedCapCert = {
      v: cert.v,
      kind: cert.kind,
      iss: cert.iss,
      issUserId: cert.issUserId,
      sub: cert.sub,
      subKem: cert.subKem,
      scope: cert.scope,
      nbf: cert.nbf,
      exp: cert.exp,
      nonce: cert.nonce,
    }
    const signed = await signCapCert(unsigned, ALICE_ED_PRIV)
    expect(signed.sig).toBe(vectors.deviceCap.signatureBase64)
  })

  it("returns a cert that round-trips through verifyCapCertSignature", async () => {
    const cert = vectors.deviceCap.cert
    const unsigned: UnsignedCapCert = {
      v: cert.v,
      kind: cert.kind,
      iss: cert.iss,
      issUserId: cert.issUserId,
      sub: cert.sub,
      subKem: cert.subKem,
      scope: cert.scope,
      nbf: cert.nbf,
      exp: cert.exp,
      nonce: cert.nonce,
    }
    const signed = await signCapCert(unsigned, ALICE_ED_PRIV)
    const ok = await verifyCapCertSignature(signed)
    expect(ok).toBe(true)
  })
})

describe("assertCapCertWellFormed", () => {
  function clone<T>(x: T): T {
    return JSON.parse(JSON.stringify(x)) as T
  }

  it("accepts the deviceCap vector", () => {
    expect(() => assertCapCertWellFormed(vectors.deviceCap.cert)).not.toThrow()
  })

  it("accepts the memberCap vector with keyring + members denies added", () => {
    const cert = clone(vectors.memberCap.cert)
    cert.scope.paths = [
      "shared-notes/*",
      "!shared-notes/_keyring",
      "!shared-notes/_members",
    ]
    expect(() => assertCapCertWellFormed(cert)).not.toThrow()
  })

  it("accepts a member cap regardless of member-specific path rules (generic-only)", () => {
    const ok = clone(vectors.memberCap.cert)
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })

  it("accepts a read-only member cap when _members deny is present", () => {
    const ok = clone(vectors.memberCap.cert)
    ok.scope.ops = ["read", "list"]
    ok.scope.paths = ["shared-notes/*", "!shared-notes/_members"]
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })

  it("does not require _members deny when no allow rule would match it", () => {
    const ok = clone(vectors.memberCap.cert)
    ok.scope.ops = ["read", "list"]
    ok.scope.paths = ["shared-notes/public/*"]
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })

  it("throws iss-userid-mismatch when issUserId doesn't match sha256(iss)", () => {
    const bad = clone(vectors.deviceCap.cert)
    bad.issUserId = "0000000000000000"
    try {
      assertCapCertWellFormed(bad)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("iss-userid-mismatch")
    }
  })

  it("throws sub-userid-mismatch when subUserId is present but doesn't match sha256(sub)", () => {
    const bad = clone(vectors.memberCap.cert)
    bad.subUserId = "0000000000000000"
    try {
      assertCapCertWellFormed(bad)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("sub-userid-mismatch")
    }
  })

  it("does NOT enforce member-specific rules (moved to starfish-sharing)", () => {
    const ok = clone(vectors.memberCap.cert)
    ok.scope.collections = ["*"]
    ok.scope.paths = ["users/{identity}/private"]
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })

  it("accepts kind=device without subUserId", () => {
    const ok = clone(vectors.deviceCap.cert)
    expect(ok.subUserId).toBeUndefined()
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })

  it("throws malformed-shape when scope.ops is not an array", () => {
    const bad = clone(vectors.deviceCap.cert) as unknown as { scope: { ops: unknown } }
    bad.scope.ops = "read"
    try {
      assertCapCertWellFormed(bad as unknown as CapCert)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("malformed-shape")
    }
  })

  it("throws malformed-shape when scope.ops contains an unknown op", () => {
    const bad = clone(vectors.deviceCap.cert)
    bad.scope.ops = ["read", "admin" as unknown as "read"]
    try {
      assertCapCertWellFormed(bad)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("malformed-shape")
    }
  })

  it("throws malformed-shape when scope is missing", () => {
    const bad = clone(vectors.deviceCap.cert) as unknown as { scope?: unknown }
    delete bad.scope
    try {
      assertCapCertWellFormed(bad as unknown as CapCert)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("malformed-shape")
    }
  })

  it("throws malformed-shape when kind is unrecognized", () => {
    const bad = clone(vectors.deviceCap.cert) as unknown as { kind: string }
    bad.kind = "root"
    try {
      assertCapCertWellFormed(bad as unknown as CapCert)
      throw new Error("did not throw")
    } catch (e) {
      expect((e as Error & { code?: string }).code).toBe("malformed-shape")
    }
  })

  it("throws malformed-shape when exp/nbf is Infinity/NaN/non-integer (no expiry-gate bypass)", () => {
    for (const badExp of [Infinity, -Infinity, NaN, 1.5]) {
      const bad = clone(vectors.deviceCap.cert) as unknown as { exp: number }
      bad.exp = badExp
      try {
        assertCapCertWellFormed(bad as unknown as CapCert)
        throw new Error(`did not throw for exp=${badExp}`)
      } catch (e) {
        expect((e as Error & { code?: string }).code).toBe("malformed-shape")
      }
    }
  })

  it("accepts whole-number-float nbf/exp (wire `.0`), matching Python", () => {
    const ok = clone(vectors.deviceCap.cert) as unknown as { nbf: number; exp: number }
    ok.nbf = vectors.deviceCap.cert.nbf + 0.0
    ok.exp = vectors.deviceCap.cert.exp + 0.0
    expect(() => assertCapCertWellFormed(ok as unknown as CapCert)).not.toThrow()
  })

  it("throws malformed-shape when nonce is not 16-byte base64", () => {
    for (const badNonce of ["", "n", "PLACEHOLDER", "AAAA", "not base64!!"]) {
      const bad = clone(vectors.deviceCap.cert)
      bad.nonce = badNonce
      try {
        assertCapCertWellFormed(bad)
        throw new Error(`did not throw for nonce=${JSON.stringify(badNonce)}`)
      } catch (e) {
        expect((e as Error & { code?: string }).code).toBe("malformed-shape")
      }
    }
  })

  it("accepts a valid 16-byte base64 nonce", () => {
    const ok = clone(vectors.deviceCap.cert)
    expect(() => assertCapCertWellFormed(ok)).not.toThrow()
  })
})

describe("pathGlobMatch (scope-barrier matcher)", () => {
  it("a single star does not cross a slash", () => {
    expect(pathGlobMatch("notes/*", "notes/a")).toBe(true)
    expect(pathGlobMatch("notes/*", "notes/a/b")).toBe(false)
  })

  it("a double star crosses slashes", () => {
    expect(pathGlobMatch("notes/**", "notes/a/b/c")).toBe(true)
    expect(pathGlobMatch("**/_keyring", "notes/sub/_keyring")).toBe(true)
  })

  it("escapes regex specials so a dot is literal", () => {
    expect(pathGlobMatch("a.b", "a.b")).toBe(true)
    expect(pathGlobMatch("a.b", "axb")).toBe(false)
  })

  it("requires a full match, not a prefix", () => {
    expect(pathGlobMatch("notes", "notes/extra")).toBe(false)
    expect(pathGlobMatch("notes/*", "other/x")).toBe(false)
  })
})
