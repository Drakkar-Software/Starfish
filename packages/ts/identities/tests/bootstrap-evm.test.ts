import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import {
  EVM_BOOTSTRAP_CHALLENGE,
  deriveRootIdentityFromEvmSignature,
  deriveRootIdentity,
} from "../src/identity.js"
import { mintDeviceCap, scopes } from "../src/cap-mint.js"
import { verifyCapCert } from "@drakkar.software/starfish-protocol"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/identity-derivation-evm.json")

interface Case {
  label: string
  privHex: string
  address: string
  challenge: string
  signatureHex: string
  edPrivHex: string
  edPubHex: string
  kemPrivHex: string
  kemPubHex: string
  userId: string
  bootstrapOrigin: { kind: "evm"; address: string }
}
interface Vector {
  defaultChallenge: string
  hkdf: { saltUtf8: string; signInfoUtf8: string; kemInfoUtf8: string }
  cases: Case[]
}

const vector = JSON.parse(readFileSync(vectorPath, "utf-8")) as Vector

function hexToBytes(h: string): Uint8Array {
  const s = h.startsWith("0x") ? h.slice(2) : h
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  return out
}
const sig = (c: Case) => hexToBytes(c.signatureHex)

describe("EVM_BOOTSTRAP_CHALLENGE", () => {
  it("matches the vector default challenge", () => {
    expect(EVM_BOOTSTRAP_CHALLENGE).toBe(vector.defaultChallenge)
  })
})

describe("deriveRootIdentityFromEvmSignature", () => {
  // 2. Known-answer vector (locks cross-language agreement with Python).
  for (const c of vector.cases) {
    it(`derives the locked vector identity: ${c.label}`, async () => {
      const id = await deriveRootIdentityFromEvmSignature({
        address: c.address,
        signature: sig(c),
        challenge: c.challenge,
      })
      expect(id.keys.edPriv).toBe(c.edPrivHex)
      expect(id.keys.edPub).toBe(c.edPubHex)
      expect(id.keys.kemPriv).toBe(c.kemPrivHex)
      expect(id.keys.kemPub).toBe(c.kemPubHex)
      expect(id.userId).toBe(c.userId)
      expect(id.bootstrapOrigin).toEqual({ kind: "evm", address: c.address })
    })
  }

  // Custom challenge namespaces identities: same wallet, different challenge.
  it("derives a distinct identity for a custom challenge", async () => {
    const def = vector.cases.find((c) => c.challenge === vector.defaultChallenge)!
    const custom = vector.cases.find((c) => c.label === "fixture-evm-custom-challenge")!
    expect(def.address).toBe(custom.address) // same wallet
    const defId = await deriveRootIdentityFromEvmSignature({ address: def.address, signature: sig(def) })
    const customId = await deriveRootIdentityFromEvmSignature({
      address: custom.address,
      signature: sig(custom),
      challenge: custom.challenge,
    })
    expect(customId.userId).not.toBe(defId.userId)
  })

  // A signature over challenge A, derived with challenge B, recovers a different
  // address → rejected. Enforces that the challenge passed matches what was signed.
  it("rejects a signature produced under a different challenge", async () => {
    const c = vector.cases.find((x) => x.challenge === vector.defaultChallenge)!
    await expect(
      deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c), challenge: "some-other-challenge" }),
    ).rejects.toThrow(/does not recover to address/)
  })

  // 1. Determinism / stability.
  it("is deterministic for the same input", async () => {
    const c = vector.cases[0]
    const a = await deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c) })
    const b = await deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c) })
    expect(a).toEqual(b)
  })

  // 3. Verification rejects a valid signature with the wrong address.
  it("rejects a valid signature presented with the wrong address", async () => {
    const [a, b] = vector.cases
    await expect(
      deriveRootIdentityFromEvmSignature({ address: b.address, signature: sig(a) }),
    ).rejects.toThrow(/does not recover to address/)
  })

  // 4. Verification rejects a tampered signature.
  it("rejects a tampered signature", async () => {
    const c = vector.cases[0]
    const bad = sig(c)
    bad[0] ^= 0xff
    await expect(
      deriveRootIdentityFromEvmSignature({ address: c.address, signature: bad }),
    ).rejects.toThrow()
  })

  // 5. Malformed input — signature length.
  it("rejects a 64-byte signature", async () => {
    const c = vector.cases[0]
    await expect(
      deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c).slice(0, 64) }),
    ).rejects.toThrow(/65-byte/)
  })

  // 5. Malformed input — address.
  it("rejects a non-hex address", async () => {
    const c = vector.cases[0]
    await expect(
      deriveRootIdentityFromEvmSignature({ address: "0x" + "zz".repeat(20), signature: sig(c) }),
    ).rejects.toThrow(/EVM address/)
  })
  it("rejects an address without 0x prefix", async () => {
    const c = vector.cases[0]
    await expect(
      deriveRootIdentityFromEvmSignature({ address: c.address.slice(2), signature: sig(c) }),
    ).rejects.toThrow(/EVM address/)
  })

  // 6. ed/kem seed separation.
  it("derives distinct ed and kem keys", async () => {
    const c = vector.cases[0]
    const id = await deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c) })
    expect(id.keys.edPriv).not.toBe(id.keys.kemPriv)
    expect(id.keys.edPub).not.toBe(id.keys.kemPub)
  })

  // 7. bootstrapOrigin recorded; address compare is case-insensitive.
  it("records bootstrapOrigin and accepts a lowercased address", async () => {
    const c = vector.cases[0]
    const id = await deriveRootIdentityFromEvmSignature({
      address: c.address.toLowerCase(),
      signature: sig(c),
    })
    expect(id.bootstrapOrigin).toEqual({ kind: "evm", address: c.address.toLowerCase() })
  })

  it("leaves bootstrapOrigin unset for passphrase-derived identities", async () => {
    const id = await deriveRootIdentity("alice-root-passphrase")
    expect(id.bootstrapOrigin).toBeUndefined()
  })

  // 8. The derived identity mints a verifiable device cap.
  it("mints a verifiable device cap from the derived identity", async () => {
    const c = vector.cases[0]
    const root = await deriveRootIdentityFromEvmSignature({ address: c.address, signature: sig(c) })
    const cap = await mintDeviceCap(
      root.keys.edPriv,
      root.keys.edPub,
      { edPubHex: root.keys.edPub, kemPubHex: root.keys.kemPub },
      scopes.rootAll(),
    )
    expect(cap.kind).toBe("device")
    expect(cap.issUserId).toBe(root.userId)
    expect((await verifyCapCert(cap, { now: cap.nbf + 5 })).ok).toBe(true)
  })

  // 9. Distinct keys → distinct identities.
  it("derives distinct identities for distinct keys", async () => {
    const [a, b] = vector.cases
    const ia = await deriveRootIdentityFromEvmSignature({ address: a.address, signature: sig(a) })
    const ib = await deriveRootIdentityFromEvmSignature({ address: b.address, signature: sig(b) })
    expect(ia.userId).not.toBe(ib.userId)
    expect(ia.keys.edPub).not.toBe(ib.keys.edPub)
  })
})
