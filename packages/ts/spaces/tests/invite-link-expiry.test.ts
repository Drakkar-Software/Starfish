/**
 * Hardening of the single-link space-invite flow:
 *   - `assertCapNotExpired`  — the shared nbf/exp guard (pure).
 *   - `createSpaceInviteLink` — owner-settable expiry (ttlSec / expiresAt) baked
 *     into the cap, and the returned `inviteUserId` revocation handle.
 *   - `joinSpaceByLink`       — refuses an expired / not-yet-valid link up front.
 *
 * Only the two network-touching collaborators are mocked (roster write +
 * keyring recipiency); the real `mintMemberCap` runs so we assert the cap's
 * actual server-enforced `nbf`/`exp`, not a stub.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"
import { generateDeviceKeys } from "@drakkar.software/starfish-identities"

import { assertCapNotExpired } from "../src/invite-helpers.js"
import { defaultSpaceLayout, defaultUserIdFromEdPub } from "../src/layout.js"
import type { Session } from "../src/session.js"

vi.mock("../src/registry.js", async (orig) => {
  const actual = await orig<typeof import("../src/registry.js")>()
  return { ...actual, addSpaceMember: vi.fn(async () => {}) }
})
vi.mock("../src/client.js", async (orig) => {
  const actual = await orig<typeof import("../src/client.js")>()
  return { ...actual, ensureSpaceKeyringRecipient: vi.fn(async () => {}) }
})

// Imported AFTER the mocks so members.ts binds the mocked collaborators.
const {
  createSpaceInviteLink,
  joinSpaceByLink,
  getSpaceInviteEntry,
  clearSpaceInviteStore,
} = await import("../src/members.js")

const DAY = 24 * 3600
const HEX32 = /^[0-9a-f]{32}$/

type Cap = { kind: string; nbf: number; exp: number; subUserId: string }

function makeOwnerSession(): Session {
  const keys = generateDeviceKeys()
  const client = { pull: vi.fn(), push: vi.fn(), peekCache: vi.fn(async () => null) }
  return {
    keys,
    userId: "owner-user-id-000000000000000000",
    name: "owner",
    layout: defaultSpaceLayout,
    userIdFromEdPub: defaultUserIdFromEdPub,
    accountClient: client,
    contentClient: client,
  } as unknown as Session
}

function tokenWithCap(cap: Partial<Cap>) {
  return { v: 1, spaceId: "sp-x", spaceName: "X", cap, key: "deadbeef", write: false } as never
}

beforeEach(() => {
  clearSpaceInviteStore()
  vi.clearAllMocks()
})

// ── assertCapNotExpired (pure) ──────────────────────────────────────────────

describe("assertCapNotExpired", () => {
  const now = () => Math.floor(Date.now() / 1000)

  it("passes for a cap whose exp is comfortably in the future", () => {
    expect(() => assertCapNotExpired({ exp: now() + 3600 }, "e")).not.toThrow()
  })

  it("passes when nbf is in the past and exp in the future (active window)", () => {
    expect(() => assertCapNotExpired({ nbf: now() - 10, exp: now() + 3600 }, "e")).not.toThrow()
  })

  it("throws 'has expired' once exp is in the past", () => {
    expect(() => assertCapNotExpired({ exp: now() - 1 }, "Nope")).toThrow(/Nope: this invite link has expired\./)
  })

  it("throws 'is not yet valid' when nbf is in the future", () => {
    expect(() => assertCapNotExpired({ nbf: now() + 3600, exp: now() + 7200 }, "Nope")).toThrow(
      /Nope: this invite link is not yet valid\./,
    )
  })

  it("is lenient: a cap with no exp/nbf is treated as non-expiring (server is the backstop)", () => {
    expect(() => assertCapNotExpired({ kind: "member" }, "e")).not.toThrow()
    expect(() => assertCapNotExpired(undefined, "e")).not.toThrow()
    expect(() => assertCapNotExpired("not-an-object", "e")).not.toThrow()
  })
})

// ── createSpaceInviteLink: owner-settable expiry + revocation handle ────────

describe("createSpaceInviteLink expiry + inviteUserId", () => {
  it("bounds the cap exp to ttlSec when provided", async () => {
    const session = makeOwnerSession()
    const { token } = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app", { ttlSec: 3600 })
    const cap = token.cap as Cap
    expect(cap.exp - cap.nbf).toBe(3600)
  })

  it("defaults to a 30-day cap when no opts are passed (backward compatible)", async () => {
    const session = makeOwnerSession()
    const { token } = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app")
    const cap = token.cap as Cap
    expect(cap.exp - cap.nbf).toBe(30 * DAY)
  })

  it("honors an absolute expiresAt (wins over the default TTL)", async () => {
    const session = makeOwnerSession()
    const future = Math.floor(Date.now() / 1000) + 12_345
    const { token } = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app", { expiresAt: future })
    expect((token.cap as Cap).exp).toBe(future)
  })

  it("returns an inviteUserId that matches the cap subject and is a stored revocation handle", async () => {
    const session = makeOwnerSession()
    const { token, link, inviteUserId } = await createSpaceInviteLink(session, "sp-9", "Team", true, "https://app", {
      ttlSec: 600,
    })
    const cap = token.cap as Cap

    expect(inviteUserId).toMatch(HEX32)
    expect(cap.subUserId).toBe(inviteUserId) // the link's ephemeral member IS inviteUserId
    expect(link).toContain("#") // secret rides in the URL fragment

    // The handle the owner passes to revokeSpaceAccess(spaceId, inviteUserId, …) is recorded.
    const stored = getSpaceInviteEntry("sp-9", inviteUserId)
    expect(stored).not.toBeNull()
    expect(stored?.cap.exp).toBe(cap.exp)
  })

  it("mints a distinct ephemeral member per call, so links are independently revocable", async () => {
    const session = makeOwnerSession()
    const a = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app", { ttlSec: 600 })
    const b = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app", { ttlSec: 600 })
    expect(a.inviteUserId).not.toBe(b.inviteUserId)
    expect(getSpaceInviteEntry("sp-1", a.inviteUserId)).not.toBeNull()
    expect(getSpaceInviteEntry("sp-1", b.inviteUserId)).not.toBeNull()
  })
})

// ── joinSpaceByLink: refuse dead links before touching the network ──────────

describe("joinSpaceByLink expiry guard", () => {
  it("rejects an expired link", async () => {
    const past = Math.floor(Date.now() / 1000) - 10
    await expect(joinSpaceByLink({} as Session, tokenWithCap({ exp: past }))).rejects.toThrow(/no longer usable.*expired/s)
  })

  it("rejects a not-yet-valid link", async () => {
    const soon = Math.floor(Date.now() / 1000) + 3600
    await expect(joinSpaceByLink({} as Session, tokenWithCap({ nbf: soon, exp: soon + 10 }))).rejects.toThrow(
      /no longer usable.*not yet valid/s,
    )
  })

  it("lets a freshly-minted (non-expired) link through the guard", async () => {
    // A link created with a real TTL must satisfy the same guard joinSpaceByLink runs.
    const session = makeOwnerSession()
    const { token } = await createSpaceInviteLink(session, "sp-1", "Team", true, "https://app", { ttlSec: 3600 })
    expect(() => assertCapNotExpired(token.cap, "no longer usable")).not.toThrow()
  })
})
