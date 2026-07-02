/**
 * v3.0 pairing helpers — vector + behavioral tests.
 *
 * Covers:
 *  - QR payload encoding (base64url(stableStringify)) against pairing-bundle.json
 *  - Bundle install roundtrip (verifies cap-cert, unwraps each CEK)
 *  - Bootstrap (self-signed device cap-cert from a passphrase)
 *  - Server-relay request/response encryption with a 6-digit code
 */

import { describe, it, expect, beforeAll } from "vitest"
import { webcrypto } from "node:crypto"
import {
  configurePlatform,
  signCapCert,
  verifyCapCert,
  verifyCapCertSignature,
} from "@drakkar.software/starfish-protocol"
import { deriveRootIdentity } from "../src/identity.js"
import { scopes } from "../src/cap-mint.js"
import {
  bootstrapRootIdentity,
  buildPairingQr,
  parsePairingQr,
  assemblePairingBundle,
  installPairingBundle,
  generateDeviceKeys,
  provisionDevice,
  installProvisionedDevice,
  deriveCodeKey,
  buildPairingRequest,
  readPairingRequest,
  buildPairingResponse,
  readPairingResponse,
  type PairingBundle,
  type PairingQrPayload,
} from "../src/pairing.js"
import vector from "../../../../tests/test-vectors/pairing-bundle.json"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: (data) => Buffer.from(data).toString("base64"),
        decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
})

// ── Helpers ───────────────────────────────────────────────────────────────────

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

function b64Decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64"))
}

interface VectorShape {
  root: { edPub: string; userId: string }
  newDevice: {
    label: string
    edPub: string
    edPriv: string
    kemPub: string
    kemPriv: string
  }
  qrPayload: {
    object: PairingQrPayload
    canonicalUtf8: string
    base64UrlEncoded: string
  }
  capCert: { cert: PairingBundle["capCert"]; canonicalSigningInput: string }
  ceks: Record<string, string>
  bundle: PairingBundle
  unwrapChecks: { collection: string; expectedCekHex: string }[]
}

const V = vector as unknown as VectorShape

// ── QR encoding ───────────────────────────────────────────────────────────────

describe("buildPairingQr / parsePairingQr — vector encoding", () => {
  it("reproduces vector.qrPayload.base64UrlEncoded exactly", () => {
    const qrNonceBytes = b64Decode(V.qrPayload.object.qrNonce)
    const encoded = buildPairingQr(
      V.newDevice.edPub,
      V.newDevice.kemPub,
      V.qrPayload.object.requestedScope,
      qrNonceBytes,
    )
    expect(encoded).toBe(V.qrPayload.base64UrlEncoded)
  })

  it("parsePairingQr decodes back to the vector object", () => {
    const parsed = parsePairingQr(V.qrPayload.base64UrlEncoded)
    expect(parsed).toEqual(V.qrPayload.object)
  })

  it("build → parse roundtrip with random nonce yields equal payload", () => {
    const nonce = new Uint8Array(16)
    for (let i = 0; i < 16; i++) nonce[i] = i
    const scope = { ops: ["read" as const], collections: ["notes"], paths: ["notes/*"] }
    const encoded = buildPairingQr("aa".repeat(32), "bb".repeat(32), scope, nonce)
    const parsed = parsePairingQr(encoded)
    expect(parsed.v).toBe(1)
    expect(parsed.devEdPub).toBe("aa".repeat(32))
    expect(parsed.devKemPub).toBe("bb".repeat(32))
    expect(parsed.requestedScope).toEqual(scope)
    // Standard base64 of nonce (16 bytes 0..15).
    expect(parsed.qrNonce).toBe(Buffer.from(nonce).toString("base64"))
  })
})

// ── Bundle install roundtrip ──────────────────────────────────────────────────

describe("installPairingBundle — vector roundtrip", () => {
  it("verifies the cap-cert and unwraps each wrapped CEK", async () => {
    const result = await installPairingBundle(
      V.bundle,
      {
        edPriv: V.newDevice.edPriv,
        edPub: V.newDevice.edPub,
        kemPriv: V.newDevice.kemPriv,
        kemPub: V.newDevice.kemPub,
      },
      // The vector cap-cert has fixed nbf/exp; evaluate the window within it.
      { now: V.bundle.capCert.nbf + 5, expectedRootEdPub: V.root.edPub },
    )

    // DeviceCredentials shape sanity checks.
    expect(result.credentials.rootEdPub).toBe(V.root.edPub)
    expect(result.credentials.userId).toBe(V.root.userId)
    expect(result.credentials.device.edPub).toBe(V.newDevice.edPub)
    expect(result.credentials.device.kemPub).toBe(V.newDevice.kemPub)
    expect(result.credentials.capCert).toEqual(V.bundle.capCert)

    // CEKs recovered byte-for-byte.
    for (const check of V.unwrapChecks) {
      const recovered = result.ceks[check.collection]
      expect(recovered).toBeDefined()
      expect(recovered!.epoch).toBe(V.bundle.wrappedCEKs[check.collection]!.epoch)
      expect(bytesToHex(recovered!.cek)).toBe(check.expectedCekHex)
    }
  })

  it("throws when the cap-cert signature is invalid", async () => {
    const tampered: PairingBundle = {
      ...V.bundle,
      capCert: {
        ...V.bundle.capCert,
        // Flip a byte of the signature.
        sig: V.bundle.capCert.sig.replace(/^./, V.bundle.capCert.sig[0] === "A" ? "B" : "A"),
      },
    }
    await expect(
      installPairingBundle(
        tampered,
        {
          edPriv: V.newDevice.edPriv,
          edPub: V.newDevice.edPub,
          kemPriv: V.newDevice.kemPriv,
          kemPub: V.newDevice.kemPub,
        },
        { now: V.bundle.capCert.nbf + 5 },
      ),
    ).rejects.toThrow()
  })
})

// ── bootstrapRootIdentity ─────────────────────────────────────────────────────

describe("bootstrapRootIdentity", () => {
  it("returns a self-signed device cap-cert whose userId matches the alice fixture", async () => {
    const creds = await bootstrapRootIdentity("alice-root-passphrase")
    // Cross-check with deriveRootIdentity — same passphrase, same userId.
    const root = await deriveRootIdentity("alice-root-passphrase")
    expect(creds.userId).toBe(root.userId)
    expect(creds.userId).toBe(V.root.userId)
    expect(creds.rootEdPub).toBe(root.keys.edPub)
    expect(creds.device.edPub).toBe(root.keys.edPub)
    expect(creds.device.kemPub).toBe(root.keys.kemPub)
    // Self-signed cert verifies (full verify — bootstrap's nbf is set to now).
    expect(creds.capCert.kind).toBe("device")
    expect(creds.capCert.iss).toBe(root.keys.edPub)
    expect(creds.capCert.sub).toBe(root.keys.edPub)
    expect(creds.capCert.subKem).toBe(root.keys.kemPub)
    const result = await verifyCapCert(creds.capCert, { now: creds.capCert.nbf + 5 })
    expect(result.ok).toBe(true)
  })

  it("rejects empty passphrases", async () => {
    await expect(bootstrapRootIdentity("")).rejects.toThrow()
  })
})

// ── assemblePairingBundle (root side) → installPairingBundle (new side) ───────

describe("assemblePairingBundle + installPairingBundle — synthetic roundtrip", () => {
  it("root device mints a cap-cert, wraps CEKs, and the new device unwraps them", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const newDeviceCreds = {
      edPriv: V.newDevice.edPriv,
      edPub: V.newDevice.edPub,
      kemPriv: V.newDevice.kemPriv,
      kemPub: V.newDevice.kemPub,
    }
    const scope = V.qrPayload.object.requestedScope
    const qr = buildPairingQr(newDeviceCreds.edPub, newDeviceCreds.kemPub, scope)
    const parsed = parsePairingQr(qr)

    const cekA = new Uint8Array(32).fill(0xaa)
    const cekB = new Uint8Array(32).fill(0xbb)

    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {
        notes: { epoch: 3, cek: cekA },
        tasks: { epoch: 7, cek: cekB },
      },
      { grantedScope: parsed.requestedScope },
    )
    expect(bundle.rootEdPub).toBe(root.keys.edPub)
    expect(bundle.capCert.kind).toBe("device")
    expect(bundle.capCert.iss).toBe(root.keys.edPub)
    expect(bundle.capCert.sub).toBe(newDeviceCreds.edPub)
    expect(await verifyCapCertSignature(bundle.capCert)).toBe(true)

    const installed = await installPairingBundle(bundle, newDeviceCreds, {
      expectedRootEdPub: root.keys.edPub,
    })
    expect(bytesToHex(installed.ceks.notes!.cek)).toBe(bytesToHex(cekA))
    expect(bytesToHex(installed.ceks.tasks!.cek)).toBe(bytesToHex(cekB))
    expect(installed.ceks.notes!.epoch).toBe(3)
    expect(installed.ceks.tasks!.epoch).toBe(7)
  })
})

// ── provisionDevice (one-way) → installProvisionedDevice ──────────────────────

describe("provisionDevice + installProvisionedDevice — one-way provisioning", () => {
  it("generates a device, mints a cap with the chosen scope + exp, and installs it", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const cek = new Uint8Array(32).fill(0xcd)
    const nbf = 1_700_000_000

    const provisioned = await provisionDevice(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      {
        scope: scopes.rootAll(),
        currentEpochByCollection: { notes: { epoch: 5, cek } },
        nbf,
        ttlSec: 3600,
      },
    )

    // A fresh device keypair was generated (32-byte hex keys).
    expect(provisioned.deviceKeys.edPub).toMatch(/^[0-9a-f]{64}$/)
    expect(provisioned.deviceKeys.kemPub).toMatch(/^[0-9a-f]{64}$/)

    // The cap is a device proxy for the root, carrying the chosen scope + window.
    expect(provisioned.bundle.capCert.kind).toBe("device")
    expect(provisioned.bundle.capCert.iss).toBe(root.keys.edPub)
    expect(provisioned.bundle.capCert.sub).toBe(provisioned.deviceKeys.edPub)
    expect(provisioned.bundle.capCert.scope).toEqual(scopes.rootAll())
    expect(provisioned.bundle.capCert.nbf).toBe(nbf)
    expect(provisioned.bundle.capCert.exp).toBe(nbf + 3600)

    // The new device installs the blob and recovers the wrapped CEK.
    const installed = await installProvisionedDevice(provisioned, { now: nbf + 5 })
    expect(installed.credentials.userId).toBe(provisioned.bundle.capCert.issUserId)
    expect(bytesToHex(installed.ceks.notes!.cek)).toBe(bytesToHex(cek))
    expect(installed.ceks.notes!.epoch).toBe(5)
  })

  it("bounds the provisioned device to a restricted (read-only) scope", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const readOnly = {
      ops: ["read", "list"] as ("read" | "list" | "write")[],
      collections: ["chat"],
      paths: ["chat/rooms/general"],
    }
    const provisioned = await provisionDevice(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      { scope: readOnly },
    )
    expect(provisioned.bundle.capCert.scope.ops).toEqual(["read", "list"])
    expect(provisioned.bundle.capCert.scope.ops).not.toContain("write")
  })

  it("reuses injected device keys (deterministic tests)", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const deviceKeys = generateDeviceKeys()
    const provisioned = await provisionDevice(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      { scope: scopes.rootAll(), deviceKeys },
    )
    expect(provisioned.deviceKeys).toEqual(deviceKeys)
    expect(provisioned.bundle.capCert.sub).toBe(deviceKeys.edPub)
    expect(provisioned.bundle.capCert.subKem).toBe(deviceKeys.kemPub)
  })
})

// ── installPairingBundle hardening (kind / window / session binding) ──────────

describe("installPairingBundle — hardening", () => {
  const newDeviceCreds = () => ({
    edPriv: V.newDevice.edPriv,
    edPub: V.newDevice.edPub,
    kemPriv: V.newDevice.kemPriv,
    kemPub: V.newDevice.kemPub,
  })
  const zeroNonceB64 = Buffer.from(new Uint8Array(16)).toString("base64")

  it("rejects a bundle carrying a member cap (only device proxies may install)", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const member = await deriveRootIdentity("bob-root-passphrase")
    const now = Math.floor(Date.now() / 1000)
    // A well-formed, validly-signed member cap whose subject is this device.
    // It passes verifyCapCert (generic well-formedness) so the kind guard is
    // what must reject it.
    const memberCert = signCapCert(
      {
        v: 1,
        kind: "member",
        iss: root.keys.edPub,
        issUserId: root.userId,
        sub: member.keys.edPub,
        subKem: member.keys.kemPub,
        subUserId: member.userId,
        scope: { ops: ["read"], collections: ["notes"], paths: ["notes/**", "!notes/_members"] },
        nbf: now,
        exp: now + 1000,
        nonce: zeroNonceB64,
      },
      root.keys.edPriv,
    )
    const bundle: PairingBundle = {
      v: 1,
      capCert: memberCert,
      rootEdPub: root.keys.edPub,
      wrappedCEKs: {},
    }
    await expect(
      installPairingBundle(
        bundle,
        { edPriv: member.keys.edPriv, edPub: member.keys.edPub, kemPriv: member.keys.kemPriv, kemPub: member.keys.kemPub },
        { now: now + 5 },
      ),
    ).rejects.toThrow(/kind="device"/)
  })

  it("rejects an expired bundle (signature alone is no longer enough)", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope)
    const parsed = parsePairingQr(qr)
    const nbf = 1_000_000
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { nbf, ttlSec: 10, grantedScope: parsed.requestedScope },
    )
    // Past exp + 300s clock skew → must be rejected.
    await expect(
      installPairingBundle(bundle, creds, { now: nbf + 10 + 301 }),
    ).rejects.toThrow(/invalid/)
    // Inside the window it still installs.
    const ok = await installPairingBundle(bundle, creds, { now: nbf + 5, expectedRootEdPub: root.keys.edPub })
    expect(ok.credentials.device.edPub).toBe(creds.edPub)
  })

  it("grants opts.grantedScope, ignoring an over-broad QR-requested scope", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    // Hostile/tampered QR requests root-all access.
    const requested = { ops: ["read", "list", "write"] as const, collections: ["*"], paths: ["**"] }
    const qr = buildPairingQr(creds.edPub, creds.kemPub, requested)
    const parsed = parsePairingQr(qr)
    const granted = { ops: ["read", "list"] as const, collections: ["notes"], paths: ["notes/**", "!notes/_members"] }
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { grantedScope: granted },
    )
    expect(bundle.capCert.scope).toEqual(granted)
    expect(bundle.capCert.scope.collections).not.toContain("*")
  })

  it("fails closed: throws when grantedScope is omitted (no defaulting to the QR scope)", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope)
    const parsed = parsePairingQr(qr)
    await expect(
      assemblePairingBundle({ edPriv: root.keys.edPriv, edPub: root.keys.edPub }, parsed, {}),
    ).rejects.toThrow(/grantedScope/)
  })

  it("binds the bundle to the pairing session via qrNonce", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    const qrNonce = new Uint8Array(16).fill(0x11)
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope, qrNonce)
    const parsed = parsePairingQr(qr)
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { grantedScope: parsed.requestedScope },
    )
    expect(bundle.qrNonce).toBe(parsed.qrNonce)
    const now = bundle.capCert.nbf + 5
    // A bundle from a different session (different qrNonce) is rejected.
    await expect(
      installPairingBundle(bundle, creds, {
        now,
        expectedQrNonce: Buffer.from(new Uint8Array(16).fill(0x22)).toString("base64"),
        expectedRootEdPub: root.keys.edPub,
      }),
    ).rejects.toThrow(/qrNonce/)
    // The matching session installs.
    const ok = await installPairingBundle(bundle, creds, {
      now,
      expectedQrNonce: parsed.qrNonce,
      expectedRootEdPub: root.keys.edPub,
    })
    expect(ok.credentials.device.edPub).toBe(creds.edPub)
  })

  it("rejects a bundle from an unexpected root when expectedRootEdPub is pinned", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const attacker = await deriveRootIdentity("attacker-root-passphrase")
    const creds = newDeviceCreds()
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope)
    const parsed = parsePairingQr(qr)
    // The attacker's OWN root assembles a validly-signed bundle for this device
    // (e.g. it answered an open rendezvous), trying to enroll it into the
    // attacker's account.
    const bundle = await assemblePairingBundle(
      { edPriv: attacker.keys.edPriv, edPub: attacker.keys.edPub },
      parsed,
      {},
      { grantedScope: parsed.requestedScope },
    )
    const now = bundle.capCert.nbf + 5
    // Pinning the real root rejects the attacker's bundle.
    await expect(
      installPairingBundle(bundle, creds, { now, expectedRootEdPub: root.keys.edPub }),
    ).rejects.toThrow(/root identity/)
    // Pinning the actual issuer installs.
    const ok = await installPairingBundle(bundle, creds, { now, expectedRootEdPub: attacker.keys.edPub })
    expect(ok.credentials.rootEdPub).toBe(attacker.keys.edPub)
  })

  it("refuses to install without a root pin or a first-contact confirmation", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope)
    const parsed = parsePairingQr(qr)
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { grantedScope: parsed.requestedScope },
    )
    const now = bundle.capCert.nbf + 5
    // Neither a pin nor a first-contact confirmation ⇒ refuse (no default trust).
    await expect(installPairingBundle(bundle, creds, { now })).rejects.toThrow(/root pinning/)
    // The correct pin installs.
    const ok = await installPairingBundle(bundle, creds, { now, expectedRootEdPub: root.keys.edPub })
    expect(ok.credentials.rootEdPub).toBe(root.keys.edPub)
  })

  it("accepts a first-contact confirmUnpinnedRoot callback and rejects when it declines", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const creds = newDeviceCreds()
    const qr = buildPairingQr(creds.edPub, creds.kemPub, V.qrPayload.object.requestedScope)
    const parsed = parsePairingQr(qr)
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { grantedScope: parsed.requestedScope },
    )
    const now = bundle.capCert.nbf + 5
    const seen: string[] = []
    const ok = await installPairingBundle(bundle, creds, {
      now,
      confirmUnpinnedRoot: (rootEdPub) => {
        seen.push(rootEdPub)
        return true
      },
    })
    // The callback saw the bundle's root fingerprint before install proceeded.
    expect(seen).toEqual([root.keys.edPub])
    expect(ok.credentials.rootEdPub).toBe(root.keys.edPub)
    // A callback that declines ⇒ refuse.
    await expect(
      installPairingBundle(bundle, creds, { now, confirmUnpinnedRoot: () => false }),
    ).rejects.toThrow(/not confirmed/)
  })
})

// ── PBKDF2 + server-relay encrypted request/response ──────────────────────────

describe("deriveCodeKey", () => {
  it("is deterministic for the same code + salt", async () => {
    const salt = new Uint8Array([1, 2, 3, 4])
    const a = await deriveCodeKey("123456", salt)
    const b = await deriveCodeKey("123456", salt)
    expect(bytesToHex(a)).toBe(bytesToHex(b))
    expect(a.byteLength).toBe(32)
  })

  it("differs for different codes", async () => {
    const salt = new Uint8Array([1, 2, 3, 4])
    const a = await deriveCodeKey("123456", salt)
    const b = await deriveCodeKey("654321", salt)
    expect(bytesToHex(a)).not.toBe(bytesToHex(b))
  })
})

describe("buildPairingRequest / readPairingRequest", () => {
  // Real keypair (from the vector) so the proof-of-possession signature
  // verifies. The PoP must be signed with the device's actual edPriv.
  const device = {
    edPriv: V.newDevice.edPriv,
    edPub: V.newDevice.edPub,
    kemPub: V.newDevice.kemPub,
  }

  // Re-encrypt a (possibly tampered) payload under the code key, exactly as a
  // relay that has learned the code would. Mirrors the library's AES-256-GCM layer.
  async function relayReencrypt(code: string, requestNonceB64: string, payload: object) {
    const keyBytes = await deriveCodeKey(code, b64Decode(requestNonceB64))
    const key = await webcrypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"])
    const iv = webcrypto.getRandomValues(new Uint8Array(12))
    const ctBuf = await webcrypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(JSON.stringify(payload)),
    )
    return {
      v: 1 as const,
      requestNonce: requestNonceB64,
      iv: Buffer.from(iv).toString("base64"),
      ct: Buffer.from(new Uint8Array(ctBuf)).toString("base64"),
    }
  }
  async function relayDecrypt(code: string, req: { requestNonce: string; iv: string; ct: string }) {
    const keyBytes = await deriveCodeKey(code, b64Decode(req.requestNonce))
    const key = await webcrypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"])
    const pt = await webcrypto.subtle.decrypt({ name: "AES-GCM", iv: b64Decode(req.iv) }, key, b64Decode(req.ct))
    return JSON.parse(new TextDecoder().decode(new Uint8Array(pt))) as Record<string, string>
  }

  it("roundtrips with the same code (valid proof-of-possession)", async () => {
    const nonce = new Uint8Array(16)
    for (let i = 0; i < 16; i++) nonce[i] = i + 1
    const enc = await buildPairingRequest(device, "123456", nonce)
    expect(enc.v).toBe(1)
    expect(enc.requestNonce).toBe(Buffer.from(nonce).toString("base64"))
    const recovered = await readPairingRequest(enc, "123456")
    expect(recovered.devEdPub).toBe(device.edPub)
    expect(recovered.devKemPub).toBe(device.kemPub)
  })

  it("fails with the wrong code", async () => {
    const nonce = new Uint8Array(16)
    const enc = await buildPairingRequest(device, "123456", nonce)
    await expect(readPairingRequest(enc, "000000")).rejects.toThrow()
  })

  it("rejects a relay that substitutes devKemPub (PoP mismatch) even with the right code", async () => {
    const code = "123456"
    const enc = await buildPairingRequest(device, code)
    // Relay knows the code: decrypt, swap devKemPub for an attacker KEM key it
    // controls, keep the original popSig, re-encrypt under the same code+nonce.
    const payload = await relayDecrypt(code, enc)
    const tampered = await relayReencrypt(code, enc.requestNonce, {
      ...payload,
      devKemPub: "cc".repeat(32), // attacker-controlled KEM pubkey
    })
    await expect(readPairingRequest(tampered, code)).rejects.toThrow(/proof-of-possession/)
  })

  it("rejects a request with no popSig field", async () => {
    const code = "123456"
    const enc = await buildPairingRequest(device, code)
    const payload = await relayDecrypt(code, enc)
    delete payload.popSig
    const stripped = await relayReencrypt(code, enc.requestNonce, payload)
    await expect(readPairingRequest(stripped, code)).rejects.toThrow(/proof-of-possession/)
  })

  it("uses the OWASP-2023 PBKDF2 iteration floor (600k) by default", async () => {
    const salt = new Uint8Array(16).fill(9)
    const def = await deriveCodeKey("123456", salt)
    const at600k = await deriveCodeKey("123456", salt, 600_000)
    const at200k = await deriveCodeKey("123456", salt, 200_000)
    expect(bytesToHex(def)).toBe(bytesToHex(at600k))
    expect(bytesToHex(def)).not.toBe(bytesToHex(at200k))
  })
}, 60_000)

describe("buildPairingResponse / readPairingResponse", () => {
  it("roundtrips a bundle through the relay", async () => {
    const nonce = new Uint8Array(16)
    for (let i = 0; i < 16; i++) nonce[i] = 7
    const requestNonceB64 = Buffer.from(nonce).toString("base64")
    const enc = await buildPairingResponse(V.bundle, "987654", requestNonceB64)
    expect(enc.v).toBe(1)
    expect(enc.requestNonce).toBe(requestNonceB64)
    const bundle = await readPairingResponse(enc, "987654")
    expect(bundle).toEqual(V.bundle)
  })
}, 60_000)
