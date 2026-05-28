import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  capCertCanonicalSigningInput,
  type CapCert,
  type UnsignedCapCert,
} from "../src/cap.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(
  __dirname,
  "../../../../tests/test-vectors/cap-cert.json",
)
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  deviceCap: { cert: CapCert; canonicalSigningInput: string }
  memberCap: { cert: CapCert; canonicalSigningInput: string }
  forgedDeviceCap: { cert: CapCert; canonicalSigningInput: string }
}

function stripSig(cert: CapCert): UnsignedCapCert {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig: _sig, ...rest } = cert
  return rest
}

describe("capCertCanonicalSigningInput", () => {
  it("matches the deviceCap vector", () => {
    const { cert, canonicalSigningInput } = vectors.deviceCap
    const unsigned = stripSig(cert)
    expect(capCertCanonicalSigningInput(unsigned)).toBe(canonicalSigningInput)
  })

  it("matches the memberCap vector", () => {
    const { cert, canonicalSigningInput } = vectors.memberCap
    const unsigned = stripSig(cert)
    expect(capCertCanonicalSigningInput(unsigned)).toBe(canonicalSigningInput)
  })

  it("matches the forgedDeviceCap vector (canonical input is independent of sig validity)", () => {
    const { cert, canonicalSigningInput } = vectors.forgedDeviceCap
    const unsigned = stripSig(cert)
    expect(capCertCanonicalSigningInput(unsigned)).toBe(canonicalSigningInput)
  })

  it("strips sig internally: a signed cert yields the same canonical input as the unsigned cert", () => {
    // The helper must strip `sig` itself (matching Python). Passing the full
    // signed cert must produce the unsigned canonical bytes, not fold `sig` in.
    const { cert, canonicalSigningInput } = vectors.deviceCap
    expect(capCertCanonicalSigningInput(cert)).toBe(canonicalSigningInput)
    expect(capCertCanonicalSigningInput(cert)).toBe(capCertCanonicalSigningInput(stripSig(cert)))
  })

  it("type-level smoke: device and member cap shapes are assignable to CapCert", () => {
    const deviceCap: CapCert = vectors.deviceCap.cert
    const memberCap: CapCert = vectors.memberCap.cert
    expect(deviceCap.kind).toBe("device")
    expect(memberCap.kind).toBe("member")
    expect(memberCap.subUserId).toBeDefined()
  })
})
