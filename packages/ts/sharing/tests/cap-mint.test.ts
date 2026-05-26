import { describe, it, expect } from "vitest"
import { deriveRootIdentity, mintDeviceCap } from "@drakkar.software/starfish-identities"
import { mintMemberCap, scopes } from "../src/cap-mint.js"
import { verifyCapCert } from "@drakkar.software/starfish-protocol"

describe("mintMemberCap", () => {
  it("returns a cert that verifies with verifyCapCert", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      scopes.writer("shared-notes"),
    )
    expect(cert.kind).toBe("member")
    expect(cert.subUserId).toBe(bob.userId)
    expect(cert.scope.collections).toEqual(["shared-notes"])
    const result = await verifyCapCert(cert, { now: cert.nbf + 5 })
    expect(result.ok).toBe(true)
  })

  it("mints a member cap with a secp256k1-schnorr KEM (decoupled KEM, now wrappable)", async () => {
    // The KEM phase relaxed the old mint gate: a non-ed25519 subKemAlg is now
    // mintable (the keyring wraps under any suite's ECDH).
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      scopes.writer("shared-notes"),
      { subKemAlg: "secp256k1-schnorr" },
    )
    expect(cert.subKemAlg).toBe("secp256k1-schnorr")
    expect(typeof cert.subKem).toBe("string")
    expect((await verifyCapCert(cert, { now: cert.nbf + 5 })).ok).toBe(true)
  })

  it("allows secp256k1 signing with an ed25519/X25519 KEM (distinct subKem emitted)", async () => {
    // The one usable decoupled combo today: sign with secp256k1, receive
    // encrypted keys under X25519. (Key bytes here are stand-ins — this exercises
    // the mint plumbing, not the curves.)
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      scopes.writer("shared-notes"),
      { subAlg: "secp256k1-schnorr", subKemAlg: "ed25519" },
    )
    expect(cert.subAlg).toBe("secp256k1-schnorr")
    expect(cert.subKemAlg).toBe("ed25519")
    expect(typeof cert.subKem).toBe("string")
  })

  it("forces scope.collections to the explicit collection arg even when scope says otherwise", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared-notes",
      {
        ops: ["read", "list", "write"],
        paths: ["shared-notes/**", "!shared-notes/_keyring", "!shared-notes/_members"],
        collections: ["this-gets-overridden"],
      },
    )
    expect(cert.scope.collections).toEqual(["shared-notes"])
  })

  it("throws member-wildcard-collections via the scopes preset that includes '*'", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "*",
        { ops: ["read", "list"], paths: ["shared-notes/*", "!shared-notes/_members"], collections: ["*"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-wildcard-collections")
  })

  it("throws member-private-path when scope.paths lands in issuer's namespace", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared-notes",
        {
          ops: ["read", "write", "list"],
          paths: ["users/{identity}/private"],
          collections: ["shared-notes"],
        },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-private-path")
  })

  it("throws member-self when sub is the issuer's own keys/userId", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: alice.keys.edPub, kemPubHex: alice.keys.kemPub, userIdHex: alice.userId },
        "shared-notes",
        scopes.writer("shared-notes"),
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-self")
  })

  it("throws member-members-not-denied when scope reaches _members without a deny", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        { ops: ["read", "list"], paths: ["shared/*"], collections: ["shared"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-members-not-denied")
  })

  it("throws member-keyring-not-denied when only the _members deny is present", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        { ops: ["read", "write"], paths: ["shared/*", "!shared/_members"], collections: ["shared"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-keyring-not-denied")
  })

  it("rejects a member cap whose '**' allow reaches _keyring across slashes (no deny)", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        // _members is denied so this isolates the _keyring barrier: the `**`
        // allow still reaches shared/_keyring across the slash, and the only
        // deny present does not cover it.
        { ops: ["read", "write"], paths: ["**", "!shared/_members"], collections: ["shared"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-keyring-not-denied")
  })

  it("rejects a member cap whose '**' allow reaches _members across slashes (no deny)", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        { ops: ["read", "list"], paths: ["**"], collections: ["shared"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-members-not-denied")
  })

  it("rejects a member cap whose bare-prefix glob (shared**) reaches _members across slashes", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        { ops: ["read", "list"], paths: ["shared**"], collections: ["shared"] },
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-members-not-denied")
  })

  it("rejects a member cap with NO scope.paths (path-unrestricted reaches _members)", async () => {
    // A cap with no `paths` is path-unrestricted: `matchScopePath(_, undefined)`
    // is true, so it would clear the gate for `shared/_members` and
    // `shared/_keyring`. The barrier must treat absent paths as an implicit
    // allow-all and reject it.
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "shared",
        { ops: ["read", "list", "write"], collections: ["shared"] }, // no `paths`
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-members-not-denied")
  })

  it("accepts member writer scope with both _keyring and _members denies", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      {
        ops: ["read", "write"],
        paths: ["shared/*", "!shared/_keyring", "!shared/_members"],
        collections: ["shared"],
      },
    )
    expect(cert.kind).toBe("member")
    expect(cert.scope.paths).toContain("!shared/_keyring")
    expect(cert.scope.paths).toContain("!shared/_members")
  })

  it("accepts read-only member cap when _members deny is present", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    const cert = await mintMemberCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
      "shared",
      { ops: ["read", "list"], paths: ["shared/*", "!shared/_members"], collections: ["shared"] },
    )
    expect(cert.kind).toBe("member")
  })
})

describe("scopes presets (sharing)", () => {
  it("readOnly grants read+list on collection paths and denies _members (owner-only)", () => {
    const s = scopes.readOnly("notes")
    expect(s.ops).toEqual(["read", "list"])
    expect(s.collections).toEqual(["notes"])
    expect(s.paths).toEqual(["notes/**", "!notes/_members"])
  })

  it("writer denylists both _keyring and _members", () => {
    const s = scopes.writer("notes")
    expect(s.ops).toContain("write")
    expect(s.paths).toContain("notes/**")
    expect(s.paths).toContain("!notes/_keyring")
    expect(s.paths).toContain("!notes/_members")
  })

  it("admin has full collection write (no denies — admin manages keyring and members)", () => {
    const s = scopes.admin("notes")
    expect(s.ops).toContain("write")
    expect(s.paths).toEqual(["notes/**"])
  })
})

describe("scopes.admin authority binding", () => {
  // The admin preset has no _keyring/_members deny. That is only valid for a
  // device cap, where the subject is a proxy for the issuer (the owner), so it
  // legitimately manages the owner's own keyring and member directory. A member
  // cap keeps its own identity and must never reach those owner-only paths, so
  // the same preset must be rejected when minted as a member cap.
  it("mintDeviceCap accepts scopes.admin (device proxies manage the owner keyring)", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const dev = await deriveRootIdentity("alice-device-passphrase")
    const cert = await mintDeviceCap(
      alice.keys.edPriv,
      alice.keys.edPub,
      { edPubHex: dev.keys.edPub, kemPubHex: dev.keys.kemPub },
      scopes.admin("notes"),
    )
    expect(cert.kind).toBe("device")
    const result = await verifyCapCert(cert, { now: cert.nbf + 5 })
    expect(result.ok).toBe(true)
  })

  it("mintMemberCap rejects scopes.admin (a member cap cannot manage _keyring/_members)", async () => {
    const alice = await deriveRootIdentity("alice-root-passphrase")
    const bob = await deriveRootIdentity("bob-root-passphrase")
    let caught: unknown
    try {
      await mintMemberCap(
        alice.keys.edPriv,
        alice.keys.edPub,
        { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
        "notes",
        scopes.admin("notes"),
      )
    } catch (e) {
      caught = e
    }
    expect(caught).toBeInstanceOf(Error)
    expect((caught as Error & { code?: string }).code).toBe("member-members-not-denied")
  })
})
