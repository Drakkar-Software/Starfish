import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  verifyCapCert,
  capCertCanonicalSigningInput,
  assertCapCertWellFormed,
  userIdFromPubHex,
  type CapCert,
} from "../src/cap.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(resolve(__dirname, "../../../../tests/test-vectors/cap-cert.json"), "utf-8"),
) as Record<string, { cert: CapCert; canonicalSigningInput: string }>

/** Run `fn`, returning the thrown error's `.code` (or "NO_THROW"). */
function codeOf(fn: () => void): string {
  try {
    fn()
    return "NO_THROW"
  } catch (e) {
    return (e as Error & { code?: string }).code ?? (e as Error).message
  }
}

const ISS = "aa".repeat(32)
function baseAudience(overrides: Record<string, unknown> = {}): unknown {
  return {
    v: 1,
    kind: "audience",
    iss: ISS,
    issUserId: userIdFromPubHex(ISS),
    scope: { ops: ["read", "list"], collections: ["broadcast"], paths: ["broadcast/**"] },
    nbf: 1000,
    exp: 2000,
    nonce: Buffer.from(new Uint8Array(16).fill(1)).toString("base64"),
    ...overrides,
  }
}

describe("audience cap-cert cross-language vectors", () => {
  for (const name of ["audienceCapOpen", "audienceCapRestricted"] as const) {
    it(`${name}: canonical signing input matches and signature verifies`, async () => {
      const v = vectors[name]!
      expect(capCertCanonicalSigningInput(v.cert)).toBe(v.canonicalSigningInput)
      const res = await verifyCapCert(v.cert, { now: v.cert.nbf + 5 })
      expect(res.ok).toBe(true)
    })
  }

  it("the open audience cap carries no sub/subKem/subUserId/aud keys", () => {
    const c = vectors.audienceCapOpen!.cert as unknown as Record<string, unknown>
    for (const k of ["sub", "subKem", "subUserId", "aud"]) expect(k in c).toBe(false)
  })
})

describe("audience cap well-formedness", () => {
  it("accepts a valid open audience cap (no aud)", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience() as never))).toBe("NO_THROW")
  })

  it("accepts a valid restricted audience cap", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: ["bb".repeat(32)] }) as never))).toBe(
      "NO_THROW",
    )
  })

  it("rejects an audience cap carrying sub or subKem", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ sub: "cc".repeat(32) }) as never))).toBe(
      "audience-has-sub",
    )
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ subKem: "cc".repeat(32) }) as never))).toBe(
      "audience-has-sub",
    )
  })

  it("rejects empty aud", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: [] }) as never))).toBe("audience-empty-aud")
  })

  it("rejects oversized aud (>64)", () => {
    const aud = Array.from({ length: 65 }, (_, i) => i.toString(16).padStart(64, "0"))
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud }) as never))).toBe("audience-aud-too-large")
  })

  it("rejects a bad aud entry (uppercase / wrong length)", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: ["AB".repeat(32)] }) as never))).toBe(
      "audience-aud-bad-entry",
    )
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: ["ab"] }) as never))).toBe(
      "audience-aud-bad-entry",
    )
  })

  it("rejects duplicate aud entries", () => {
    const dup = "bb".repeat(32)
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: [dup, dup] }) as never))).toBe(
      "audience-aud-dup",
    )
  })

  it("rejects an explicit null subject on an audience cap (parity with Python)", () => {
    // A present `sub: null` is *present*, not absent — must be rejected, just
    // like Python's presence check. Guards against a cross-language split.
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ sub: null }) as never))).toBe(
      "audience-has-sub",
    )
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ subKem: null }) as never))).toBe(
      "audience-has-sub",
    )
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ subUserId: null }) as never))).toBe(
      "audience-has-sub",
    )
  })

  it("rejects an explicit null aud on an audience cap (bad list, not open)", () => {
    expect(codeOf(() => assertCapCertWellFormed(baseAudience({ aud: null }) as never))).toBe(
      "audience-aud-bad-entry",
    )
  })

  it("rejects a member cap carrying aud", () => {
    const member = {
      v: 1,
      kind: "member",
      iss: ISS,
      issUserId: userIdFromPubHex(ISS),
      sub: "dd".repeat(32),
      subKem: "ee".repeat(32),
      subUserId: userIdFromPubHex("dd".repeat(32)),
      scope: { ops: ["read"], collections: ["x"] },
      nbf: 1000,
      exp: 2000,
      nonce: Buffer.from(new Uint8Array(16).fill(1)).toString("base64"),
      aud: ["bb".repeat(32)],
    }
    expect(codeOf(() => assertCapCertWellFormed(member as never))).toBe("non-audience-has-aud")
    // A present `aud: null` on a non-audience cap is also rejected (parity with Python).
    expect(codeOf(() => assertCapCertWellFormed({ ...member, aud: null } as never))).toBe(
      "non-audience-has-aud",
    )
  })
})
