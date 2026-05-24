import { describe, it, expect } from "vitest"
import { deriveRootIdentity } from "../src/identity.js"
import { mintDeviceCap, scopes } from "../src/cap-mint.js"
import { verifyCapCert } from "@drakkar.software/starfish-protocol"

describe("mintDeviceCap", () => {
  it("returns a cert that verifies with verifyCapCert", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub },
      scopes.rootAll(),
    )
    expect(cert.kind).toBe("device")
    expect(cert.iss).toBe(alice.keys.edPub)
    expect(cert.issUserId).toBe(alice.userId)
    expect(cert.sub).toBe(bob.keys.edPub)
    expect(cert.subKem).toBe(bob.keys.kemPub)
    expect(cert.sig).toMatch(/^[A-Za-z0-9+/=]+$/)
    const now = cert.nbf + 5
    const result = await verifyCapCert(cert, { now })
    expect(result.ok).toBe(true)
  })

  it("sets nbf/exp from opts.ttlSec", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const nbf = 1_700_000_000
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub },
      scopes.rootAll(),
      { nbf, ttlSec: 60 },
    )
    expect(cert.nbf).toBe(nbf)
    expect(cert.exp).toBe(nbf + 60)
  })

  it("injects opts.nonce verbatim (base64-encoded on the cert)", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    // Known 16-byte nonce: 0x00..0x0f
    const known = new Uint8Array([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ])
    const expected = Buffer.from(known).toString("base64")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub },
      scopes.rootAll(),
      { nonce: known },
    )
    expect(cert.nonce).toBe(expected)
  })

  it("mints an ed25519-sign + secp256k1-schnorr-KEM cap (decoupled KEM, now wrappable)", async () => {
    // The KEM phase relaxed the old mint gate: a non-ed25519 subKemAlg is now
    // mintable (the keyring wraps under any suite's ECDH).
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub },
      scopes.rootAll(),
      { subKemAlg: "secp256k1-schnorr" },
    )
    expect(cert.subKemAlg).toBe("secp256k1-schnorr")
    expect(typeof cert.subKem).toBe("string") // distinct KEM key emitted
    expect((await verifyCapCert(cert, { now: cert.nbf + 5 })).ok).toBe(true)
  })

  it("allows secp256k1-schnorr signing with an X25519 (ed25519) KEM", async () => {
    // The one usable decoupled combo today (key bytes are stand-ins).
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub },
      scopes.rootAll(),
      { subAlg: "secp256k1-schnorr", subKemAlg: "ed25519" },
    )
    expect(cert.subAlg).toBe("secp256k1-schnorr")
    expect(cert.subKemAlg).toBe("ed25519")
    expect(typeof cert.subKem).toBe("string")
  })
})

describe("scopes presets (identities)", () => {
  it("rootAll grants everything (**, not *)", () => {
    const s = scopes.rootAll()
    expect(s.collections).toEqual(["*"])
    expect(s.paths).toEqual(["**"])
  })
})
