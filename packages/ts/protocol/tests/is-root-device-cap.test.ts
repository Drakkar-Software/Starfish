import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { isRootDeviceCap, type CapCert } from "../src/cap.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/cap-cert.json")
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  deviceCap: { cert: CapCert }
  memberCap: { cert: CapCert }
}

describe("isRootDeviceCap", () => {
  it("is true for a self-signed device cap (iss === sub) — the root device", () => {
    // The root device's cap is minted by the root for itself, so iss === sub.
    const cert: CapCert = { ...vectors.deviceCap.cert, kind: "device", sub: vectors.deviceCap.cert.iss }
    expect(isRootDeviceCap(cert)).toBe(true)
  })

  it("is false for a paired device cap (iss !== sub)", () => {
    expect(vectors.deviceCap.cert.iss).not.toBe(vectors.deviceCap.cert.sub)
    expect(isRootDeviceCap(vectors.deviceCap.cert)).toBe(false)
  })

  it("is false for a member cap", () => {
    expect(isRootDeviceCap(vectors.memberCap.cert)).toBe(false)
  })

  it("is false for a member cap even if iss === sub (kind must be device)", () => {
    const cert: CapCert = { ...vectors.memberCap.cert, kind: "member", sub: vectors.memberCap.cert.iss }
    expect(isRootDeviceCap(cert)).toBe(false)
  })
})
