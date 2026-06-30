/**
 * Regression tests for `resolveEntryClient` / `resolveTrustedAdders`.
 *
 * Bug: a `kind:"link"` access entry (the path a space invite-link joiner uses) never
 * surfaced `capIss`, so `resolveTrustedAdders` fell back to `reg.owner` (a userId hash,
 * never equal to an edPub) or the joiner's own owner-trust set — never the actual
 * owner edPub that signed the link's cap and every keyring entry it added. Every
 * keyring recipient entry was then rejected as "not a trusted adder" and the joiner
 * could decrypt nothing (wedding/guests/vendors/invitation types all failed identically
 * on both read and write).
 *
 * Fix: the `link` branch of `resolveEntryClient` now returns `capIss: entry.cap.iss`,
 * mirroring the `member` branch (`LinkAccessPayload.cap` is already a parsed object —
 * no `JSON.parse` needed, unlike the member entry's `cap: string`).
 *
 * R1: link entry surfaces capIss from entry.cap.iss (the fix).
 * R2: member entry still surfaces capIss from the parsed cap JSON (unchanged behavior).
 * R3: no entry → no capIss, client falls back to session.contentClient.
 * R4: resolveTrustedAdders — link entry's capIss (owner edPub) takes precedence over
 *     reg.owner and the joiner's own owner-trust set, so the owner-added keyring entry
 *     (addedBy === ownerEdPub) is now in the trusted set.
 * R5: resolveTrustedAdders — without capIss (pre-fix shape), the owner's edPub is NOT
 *     reachable via reg.owner (a userId hash) or the joiner's own owner-trust set —
 *     documents the exact failure mode the fix closes.
 */
import { describe, it, expect } from "vitest"
import { resolveEntryClient, resolveTrustedAdders } from "../src/space-access.js"
import type { Session } from "../src/session.js"
import type { SpaceAccessEntry } from "../src/space-access-store.js"

const OWNER_EDPUB = "0a9f5ffbca9554071473f3f2f810c35ee15dec1dd5ef6fc55d18f2a955bc1f2c"
const JOINER_EDPUB = "joiner-edpub-deadbeef"
const OWNER_USERID = "ownerUserIdHash32CharsLongLike"

function fakeSession(overrides: Partial<Session> = {}): Session {
  return {
    userId: "joiner-user-id",
    name: "joiner",
    keys: { edPub: JOINER_EDPUB, edPriv: "joiner-edpriv", kemPub: "joiner-kempub", kemPriv: "joiner-kempriv" },
    contentCap: null,
    accountCap: null,
    contentClient: { kind: "content-client" } as unknown as Session["contentClient"],
    accountClient: { kind: "account-client" } as unknown as Session["accountClient"],
    spacesRegistryClient: { kind: "registry-client" } as unknown as Session["spacesRegistryClient"],
    spacesKeyringClient: { kind: "keyring-client" } as unknown as Session["spacesKeyringClient"],
    fingerprint: "AAAA · BBBB · CCCC",
    // Joiner's own session is rooted at its own edPub (no paired device) — the
    // pre-fix fallback that incorrectly gets used when capIss is missing.
    ownerEdPub: JOINER_EDPUB,
    layout: {} as unknown as Session["layout"],
    userIdFromEdPub: async () => "x",
    spaceIdPrefix: "sp-",
    nodeIdPrefix: "obj-",
    inboxAadNamespace: "starfish:inbox:v1",
    kvKeyPrefix: "starfish.spaceaccess.",
    baseUrl: "https://sync.example.com",
    namespace: "fiance",
    ...overrides,
  }
}

describe("resolveEntryClient", () => {
  it("R1: link entry surfaces capIss from entry.cap.iss", () => {
    const entry: SpaceAccessEntry = {
      kind: "link",
      cap: { iss: OWNER_EDPUB },
      key: "ephemeral-edpriv",
      kemPriv: "ephemeral-kempriv",
      kemPub: "ephemeral-kempub",
      write: false,
    }
    const { capIss } = resolveEntryClient(entry, fakeSession())
    expect(capIss).toBe(OWNER_EDPUB)
  })

  it("R2: member entry still surfaces capIss from the parsed cap JSON", () => {
    const entry: SpaceAccessEntry = {
      kind: "member",
      cap: JSON.stringify({ iss: OWNER_EDPUB }),
    }
    const { capIss } = resolveEntryClient(entry, fakeSession())
    expect(capIss).toBe(OWNER_EDPUB)
  })

  it("R3: no entry → no capIss", () => {
    const { capIss, client } = resolveEntryClient(null, fakeSession())
    expect(capIss).toBeUndefined()
    expect(client).toBeDefined()
  })
})

describe("resolveTrustedAdders — link-join keyring trust (regression for 'not a trusted adder')", () => {
  it("R4: link entry's capIss makes the owner-added keyring entry trusted", () => {
    const entry: SpaceAccessEntry = {
      kind: "link",
      cap: { iss: OWNER_EDPUB },
      key: "ephemeral-edpriv",
      kemPriv: "ephemeral-kempriv",
      kemPub: "ephemeral-kempub",
      write: false,
    }
    const session = fakeSession()
    const { capIss } = resolveEntryClient(entry, session)
    const trustedAdders = resolveTrustedAdders(capIss, { owner: OWNER_USERID }, session)

    // The keyring entry the owner wrote has addedBy === OWNER_EDPUB — it must be trusted.
    expect(trustedAdders).toContain(OWNER_EDPUB)
  })

  it("R5: without capIss (pre-fix shape), the owner's edPub is unreachable", () => {
    const session = fakeSession()
    const trustedAdders = resolveTrustedAdders(undefined, { owner: OWNER_USERID }, session)

    // reg.owner is a userId hash, never an edPub; the joiner's own owner-trust set is
    // rooted at its own edPub. Neither path reaches OWNER_EDPUB — this is exactly why
    // `addedBy 0a9f5ffb… is not a trusted adder` fired before the fix.
    expect(trustedAdders).not.toContain(OWNER_EDPUB)
  })
})
