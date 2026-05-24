import { describe, it, expect } from "vitest"
import { deriveRootIdentity } from "@drakkar.software/starfish-identities"
import { verifyCapCert } from "@drakkar.software/starfish-protocol"
import {
  createPublicLink,
  parsePublicLink,
  redeemPublicLink,
  mintAudienceCap,
  scopes,
} from "../src/index.js"

const ALICE = () => deriveRootIdentity("alice-root-passphrase")
const BOB = () => deriveRootIdentity("bob-root-passphrase")

async function codeOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn()
    return "NO_THROW"
  } catch (e) {
    return (e as Error & { code?: string }).code ?? (e as Error).message
  }
}

describe("createPublicLink / parsePublicLink / redeemPublicLink", () => {
  it("open link: mints an audience cap with no aud, round-trips, and verifies", async () => {
    const alice = await ALICE()
    const link = await createPublicLink({
      issEdPrivHex: alice.keys.edPriv,
      issEdPubHex: alice.keys.edPub,
      collection: "broadcast",
      scope: scopes.readOnly("broadcast"),
      nbf: 1_747_000_000,
      ttlSec: 3600,
    })
    expect(link.cap.kind).toBe("audience")
    expect("aud" in link.cap).toBe(false)
    expect("sub" in link.cap).toBe(false)
    const parsed = parsePublicLink(link.fragment)
    expect(parsed.cap).toEqual(link.cap)
    const res = await verifyCapCert(link.cap, { now: link.cap.nbf + 5 })
    expect(res.ok).toBe(true)
  })

  it("restricted link: aud is exactly the allowed identities", async () => {
    const alice = await ALICE()
    const bob = await BOB()
    const link = await createPublicLink({
      issEdPrivHex: alice.keys.edPriv,
      issEdPubHex: alice.keys.edPub,
      collection: "broadcast",
      scope: scopes.readOnly("broadcast"),
      allowedIdentities: [bob.keys.edPub],
    })
    expect(link.cap.aud).toEqual([bob.keys.edPub])
    expect(parsePublicLink(link.fragment).cap).toEqual(link.cap)
  })

  it("redeemPublicLink signs with the redeemer's key and sets X-Starfish-Pub", async () => {
    const alice = await ALICE()
    const bob = await BOB()
    const link = await createPublicLink({
      issEdPrivHex: alice.keys.edPriv,
      issEdPubHex: alice.keys.edPub,
      collection: "broadcast",
      scope: scopes.readOnly("broadcast"),
      allowedIdentities: [bob.keys.edPub],
    })
    const headers = await redeemPublicLink(parsePublicLink(link.fragment), {
      redeemerEdPrivHex: bob.keys.edPriv,
      redeemerEdPubHex: bob.keys.edPub,
      method: "GET",
      pathAndQuery: "/pull/broadcast/post-1",
      host: "api.example.com",
    })
    expect(headers["X-Starfish-Pub"]).toBe(bob.keys.edPub)
    expect(headers.Authorization.startsWith("Cap ")).toBe(true)
    expect(typeof headers["X-Starfish-Sig"]).toBe("string")
  })

  it("parsePublicLink rejects a malformed fragment", () => {
    expect(() => parsePublicLink("!!!not-base64url!!!")).toThrow()
  })

  it("rejects an explicitly-empty allowedIdentities list (no silent open-link footgun)", async () => {
    const alice = await ALICE()
    expect(
      await codeOf(() =>
        createPublicLink({
          issEdPrivHex: alice.keys.edPriv,
          issEdPubHex: alice.keys.edPub,
          collection: "broadcast",
          scope: scopes.readOnly("broadcast"),
          allowedIdentities: [],
        }),
      ),
    ).toBe("audience-empty")
  })
})

describe("mintAudienceCap expiry resolution", () => {
  it("expiresAt wins over ttlSec", async () => {
    const alice = await ALICE()
    const cap = await mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", scopes.readOnly("broadcast"), {
      nbf: 1_000_000,
      ttlSec: 10,
      expiresAt: 2_000_000,
    })
    expect(cap.exp).toBe(2_000_000)
  })

  it("rejects expiresAt that is not after nbf", async () => {
    const alice = await ALICE()
    expect(
      await codeOf(() =>
        mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", scopes.readOnly("broadcast"), {
          nbf: 2_000_000,
          expiresAt: 1_000_000,
        }),
      ),
    ).toBe("expiresAt-not-after-nbf")
  })

  it("ttlSec-only path and 30-day default", async () => {
    const alice = await ALICE()
    const withTtl = await mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", scopes.readOnly("broadcast"), {
      nbf: 1_000_000,
      ttlSec: 42,
    })
    expect(withTtl.exp).toBe(1_000_042)
    const def = await mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", scopes.readOnly("broadcast"), {
      nbf: 1_000_000,
    })
    expect(def.exp).toBe(1_000_000 + 30 * 24 * 3600)
  })
})

describe("assertAudienceCapShape barriers (via mint)", () => {
  it("rejects a scope that reaches <col>/_members without a deny", async () => {
    const alice = await ALICE()
    expect(
      await codeOf(() =>
        mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", {
          ops: ["read", "list"],
          collections: ["broadcast"],
          paths: ["broadcast/**"], // matches broadcast/_members with no deny
        }),
      ),
    ).toBe("audience-members-not-denied")
  })

  it("rejects a scope reaching the issuer's private namespace", async () => {
    const alice = await ALICE()
    expect(
      await codeOf(() =>
        mintAudienceCap(alice.keys.edPriv, alice.keys.edPub, "broadcast", {
          ops: ["read", "list"],
          collections: ["broadcast"],
          paths: [`users/${alice.userId}/secret`, "!broadcast/_members"],
        }),
      ),
    ).toBe("audience-private-path")
  })
})
