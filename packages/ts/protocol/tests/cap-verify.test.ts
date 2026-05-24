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
  crossSuiteMemberCap: { cert: CapCert; canonicalSigningInput: string; signatureBase64: string }
  mixedKemMemberCap: { cert: CapCert; canonicalSigningInput: string; signatureBase64: string }
  strippedSubAlgMemberCap: { cert: CapCert; expectVerify: false }
  swappedSubAlgMemberCap: { cert: CapCert; expectVerify: false }
}

// Alice's root edPriv — deriveRootIdentity("alice-root-passphrase").keys.edPriv.
// Hardcoded here to keep the protocol package dependency-free (no client dep).
// Ed25519 is deterministic, so signing the same canonical input with this priv
// yields the vector's signature byte-for-byte.
// deriveRootIdentity("alice-root-passphrase").keys.edPriv after Argon2id+HKDF
// pipeline (matches tests/test-vectors/multi-recipient-wrap.json#fixtures.alice_root.edPriv).
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

  it("verifies the crossSuiteMemberCap vector (ed25519 sig over a secp256k1-subject cap)", async () => {
    // The cap `sig` is Ed25519 (issAlg) even though the subject suite is
    // secp256k1 — the non-default subAlg is folded into the signed bytes.
    const ok = await verifyCapCertSignature(vectors.crossSuiteMemberCap.cert)
    expect(ok).toBe(true)
  })

  it("verifies the mixedKemMemberCap vector (decoupled subKemAlg in the signed bytes)", async () => {
    const ok = await verifyCapCertSignature(vectors.mixedKemMemberCap.cert)
    expect(ok).toBe(true)
  })

  it("rejects strippedSubAlgMemberCap (subAlg downgrade caught cross-language)", async () => {
    // Cross-suite cert's ed25519 signature, but the signed `subAlg` tag was
    // stripped → canonical input differs → verification fails.
    expect(vectors.strippedSubAlgMemberCap.expectVerify).toBe(false)
    const ok = await verifyCapCertSignature(vectors.strippedSubAlgMemberCap.cert)
    expect(ok).toBe(false)
  })

  it("rejects swappedSubAlgMemberCap (subAlg swapped to ed25519 caught)", async () => {
    expect(vectors.swappedSubAlgMemberCap.expectVerify).toBe(false)
    const ok = await verifyCapCertSignature(vectors.swappedSubAlgMemberCap.cert)
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
      issAlg: base.issAlg,
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
    // 60s before nbf with 300s default skew → still ok
    const result = await verifyCapCert(cert, { now: cert.nbf - 60 })
    expect(result.ok).toBe(true)
  })

  it("treats the exact expiry+skew instant as still valid and one second past as expired", async () => {
    // The expiry gate is `now > exp + skew` (strict): the boundary second is
    // valid, the next is expired. Pins the off-by-one against a `>=` rewrite
    // and keeps it identical to the Python comparator.
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
    // An empty ops array passes the vacuous membership check and verify is ok,
    // but the resolver synthesizes no roles from zero ops. Pin that empty scope
    // is structurally valid rather than rejected or treated as a wildcard.
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
    // Without an explicit `exp > nbf` check, the instant where the skew margins
    // overlap (`nbf - exp <= 2*skew`) would clear both time gates — so the
    // verifier rejects `exp <= nbf` up front, even at a `now` inside that overlap.
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
    // scope.ops is a string, not an array. Without shape validation the
    // resolver would iterate it character-by-character into fabricated roles.
    const malformed = {
      v: base.v,
      kind: base.kind,
      issAlg: base.issAlg,
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
    // The signature is valid over the malformed bytes — only the structural
    // check stands between this cert and role synthesis.
    expect(await verifyCapCertSignature(signed)).toBe(true)
    const result = await verifyCapCert(signed, { now: base.nbf + 100 })
    expect(result.ok).toBe(false)
    expect(result.reason).toBe("malformed-shape")
  })
})

describe("signCapCert", () => {
  it("produces the vector signature when re-signing the deviceCap canonical input with alice's edPriv", async () => {
    // Derive alice's edPriv from the existing identity primitive via a
    // dependency-free constant (Ed25519 determinism guarantees that any
    // sign of the same canonical input with the same edPriv → same sig).
    const cert = vectors.deviceCap.cert
    const unsigned: UnsignedCapCert = {
      v: cert.v,
      kind: cert.kind,
      issAlg: cert.issAlg,
      subAlg: cert.subAlg,
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
      issAlg: cert.issAlg,
      subAlg: cert.subAlg,
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

  it("accepts the crossSuiteMemberCap vector (secp256k1 subject omits subKem)", () => {
    // secp256k1 reuses its sign key for the KEM, so well-formedness requires
    // subKem to be ABSENT — this vector pins that the predicate accepts it.
    expect(() => assertCapCertWellFormed(vectors.crossSuiteMemberCap.cert)).not.toThrow()
  })

  it("accepts the mixedKemMemberCap vector (subKemAlg decoupled from subAlg)", () => {
    // subAlg=secp256k1 but subKemAlg=ed25519 → a distinct X25519 subKem is
    // required; pins that the predicate accepts the decoupled-KEM shape.
    expect(() => assertCapCertWellFormed(vectors.mixedKemMemberCap.cert)).not.toThrow()
  })

  it("accepts the memberCap vector with keyring + members denies added", () => {
    // The pinned vector lacks both `!shared-notes/_keyring` and
    // `!shared-notes/_members`; both are now required for member caps that
    // grant `write` and any access (including read) on a path matching those.
    const cert = clone(vectors.memberCap.cert)
    cert.scope.paths = [
      "shared-notes/*",
      "!shared-notes/_keyring",
      "!shared-notes/_members",
    ]
    expect(() => assertCapCertWellFormed(cert)).not.toThrow()
  })

  // Member-specific shape rules (member-self / member-private-path /
  // member-members-not-denied / member-keyring-not-denied / …) moved to
  // `assertMemberCapShape` in `@drakkar.software/starfish-sharing`; their
  // tests live there. The protocol's `assertCapCertWellFormed` now only
  // enforces the generic iss/sub-userId relations.

  it("accepts a member cap regardless of member-specific path rules (generic-only)", () => {
    // No `_members`/`_keyring` deny — protocol no longer rejects this; the
    // sharing plugin owns that rule now.
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
    // A scope that only allows a specific subpath cannot reach `_members`,
    // so no deny is required (parallel to the keyring rule's behavior).
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
    // A member cap with `*` collections + a private-namespace path used to
    // throw here; the protocol layer is now kind-agnostic and accepts it.
    // `assertMemberCapShape` (starfish-sharing) is the authoritative owner.
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
      // Set in-memory (not via JSON, which would coerce Infinity→null).
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
    // A cap-cert serialized with a trailing `.0` parses to the same IEEE-754
    // value as the integer in JS; Python now accepts it too (was rejected),
    // so a cert authenticates identically on a TS and a Python server.
    const ok = clone(vectors.deviceCap.cert) as unknown as { nbf: number; exp: number }
    ok.nbf = vectors.deviceCap.cert.nbf + 0.0
    ok.exp = vectors.deviceCap.cert.exp + 0.0
    expect(() => assertCapCertWellFormed(ok as unknown as CapCert)).not.toThrow()
  })

  it("throws malformed-shape when nonce is not 16-byte base64", () => {
    // Without a length/charset constraint a self-issuer could reuse a nonce or
    // use a degenerate one, weakening per-cap revocation (keyed on the nonce).
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
    // `**` must reach across path segments — the member-cap `!col/_keyring`
    // deny relies on it, so a matcher that stopped at a slash would clear a cap
    // the resolver later grants.
    expect(pathGlobMatch("notes/**", "notes/a/b/c")).toBe(true)
    expect(pathGlobMatch("**/_keyring", "notes/sub/_keyring")).toBe(true)
  })

  it("escapes regex specials so a dot is literal", () => {
    // 'a.b' matches only 'a.b', never 'axb' — a crafted collection name can't
    // widen a scope barrier by smuggling a regex metacharacter.
    expect(pathGlobMatch("a.b", "a.b")).toBe(true)
    expect(pathGlobMatch("a.b", "axb")).toBe(false)
  })

  it("requires a full match, not a prefix", () => {
    expect(pathGlobMatch("notes", "notes/extra")).toBe(false)
    expect(pathGlobMatch("notes/*", "other/x")).toBe(false)
  })
})
