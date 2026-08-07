/**
 * Tests for the device-code space-join primitive (`join-request.ts`).
 *
 * The crypto is REAL (ed25519 PoP signatures, kemSig, KEM seal/unseal) — only
 * the transport is faked, by an in-memory slot store that reproduces the
 * server's CAS contract: a push must present the slot's current hash, `null`
 * for a slot that does not exist yet, or it 409s with a `ConflictError`. That
 * is the property most of the security-relevant assertions here rest on, so
 * faking it loosely would make the suite vacuous.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"

import { ConflictError, StarfishHttpError } from "@drakkar.software/starfish-client"

// ── Fake rendezvous server (hoisted before the module under test) ─────────────

interface Slot {
  data: Record<string, unknown>
  hash: string
}

const store = new Map<string, Slot>()
let hashCounter = 0
/** Number of upcoming pulls that should fail with a transient 503. */
let pullFailures = 0
/** Number of upcoming pushes that should 409 regardless of baseHash — simulates
 *  sustained contention from another writer racing every retry attempt. */
let pushConflicts = 0

/** `/pull/x` and `/push/x` address the SAME document — key the store on `x`. */
function docKey(path: string): string {
  return path.replace(/^\/(pull|push)\//, "")
}

const pushSpy = vi.fn()

function fakeClient() {
  return {
    async pull(path: string) {
      if (pullFailures > 0) {
        pullFailures -= 1
        throw new StarfishHttpError(503, "transient")
      }
      const slot = store.get(docKey(path))
      if (!slot) throw new StarfishHttpError(404, "not found")
      return { data: slot.data, hash: slot.hash, timestamp: 1 }
    },
    async push(path: string, data: Record<string, unknown>, baseHash: string | null) {
      pushSpy(path, data, baseHash)
      const key = docKey(path)
      const current = store.get(key)
      if (pushConflicts > 0) {
        pushConflicts -= 1
        throw new ConflictError(current?.hash ?? "")
      }
      const expected = current ? current.hash : null
      if (baseHash !== expected) throw new ConflictError(current?.hash ?? "")
      hashCounter += 1
      const hash = `h${hashCounter}`
      store.set(key, { data, hash })
      return { hash, timestamp: 1 }
    },
  }
}

vi.mock("../src/client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client.js")>()
  return { ...actual, makeAnonSpaceClient: vi.fn(() => fakeClient()) }
})

// ── Imports (after the mock) ──────────────────────────────────────────────────

import {
  createSpaceJoinRequest,
  parseSpaceJoinRequest,
  startSpaceJoinRequest,
  fetchSpaceJoinRequestByCode,
  joinRequestFromSpaceJoinRequest,
  publishSpaceJoinGrant,
  clearSpaceJoinGrant,
  fetchSpaceJoinGrant,
  awaitSpaceJoinGrant,
  SpaceJoinGrantIntegrityError,
  type SpaceJoinRequestPayload,
  type SpaceJoinRequestSession,
} from "../src/join-request.js"
import { defaultSpaceLayout, defaultUserIdFromEdPub } from "../src/layout.js"
import { verifyKemSig } from "../src/request-verify.js"
import { generateDeviceKeys } from "@drakkar.software/starfish-identities"
import type { SealerKeys } from "@drakkar.software/starfish-keyring"

const RENDEZVOUS = { baseUrl: "https://sync.test", namespace: "dk" }
const ORIGIN = "https://myapp.example"

/** A stand-in for the approving wallet's root Ed25519 keypair. */
function makeSealer(): SealerKeys {
  const k = generateDeviceKeys()
  return { edPrivHex: k.edPriv, edPubHex: k.edPub }
}

const GRANT = { spaceId: "sp-abc123", cap: { kind: "member", sub: "whatever" } }

function slotOf(code: string): Slot | undefined {
  return store.get(docKey(defaultSpaceLayout.joinSessionPull(code)))
}

/** Full happy path up to (not including) the grant publish. */
async function publishedRequest(): Promise<{ session: SpaceJoinRequestSession }> {
  const session = startSpaceJoinRequest({ origin: ORIGIN, rendezvous: RENDEZVOUS })
  await session.publish()
  return { session }
}

/** Full happy path through an approved grant. Returns the sealer for TOFU tests. */
async function approvedSession(): Promise<{ session: SpaceJoinRequestSession; sealer: SealerKeys }> {
  const { session } = await publishedRequest()
  const sealer = makeSealer()
  const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
  if (!found) throw new Error("test setup: request not found")
  await publishSpaceJoinGrant({
    code: session.code,
    request: found.request,
    sealer,
    grant: GRANT,
    rendezvous: RENDEZVOUS,
    baseHash: found.hash,
  })
  return { session, sealer }
}

beforeEach(() => {
  store.clear()
  hashCounter = 0
  pullFailures = 0
  pushConflicts = 0
  pushSpy.mockClear()
})

afterEach(() => {
  vi.useRealTimers()
})

// ── Layout ────────────────────────────────────────────────────────────────────

describe("SpaceLayout join-session paths", () => {
  it("defaults to _pairing/session/{code} on one slot for both phases", () => {
    expect(defaultSpaceLayout.joinSessionPull("ABCD2345")).toBe("/pull/_pairing/session/ABCD2345")
    expect(defaultSpaceLayout.joinSessionPush("ABCD2345")).toBe("/push/_pairing/session/ABCD2345")
  })

  it("percent-encodes a human-typed code so it cannot escape the path", () => {
    expect(defaultSpaceLayout.joinSessionPull("../evil")).toBe("/pull/_pairing/session/..%2Fevil")
  })
})

// ── createSpaceJoinRequest ────────────────────────────────────────────────────

describe("createSpaceJoinRequest", () => {
  it("mints an 8-char code from the unambiguous alphabet", () => {
    for (let i = 0; i < 50; i++) {
      const { code } = createSpaceJoinRequest({ origin: ORIGIN })
      expect(code).toMatch(/^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/)
    }
  })

  it("produces a request that parses and verifies under its own code", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN, label: "My App" })
    expect(() => parseSpaceJoinRequest(JSON.stringify(request), code)).not.toThrow()
    expect(request.phase).toBe("request")
    expect(request.label).toBe("My App")
  })

  it("carries a joinRequestKemSig that verifies against devEdPub/devKemPub", () => {
    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    expect(verifyKemSig(request.devEdPub, request.devKemPub, request.joinRequestKemSig)).toBe(true)
  })

  it("does NOT embed rendezvous coordinates or the code in the document body", () => {
    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    expect(request).not.toHaveProperty("rendezvous")
    expect(request).not.toHaveProperty("code")
  })

  it("clamps an oversized ttlSec to the one-hour maximum parse will accept", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN, ttlSec: 365 * 24 * 60 * 60 })
    const windowMs = Date.parse(request.expiresAt) - Date.now()
    expect(windowMs).toBeLessThanOrEqual(60 * 60 * 1000)
    // The whole point of clamping: what we create must be what parse accepts.
    expect(() => parseSpaceJoinRequest(JSON.stringify(request), code)).not.toThrow()
  })
})

// ── Create-only CAS on the request write ──────────────────────────────────────

describe("startSpaceJoinRequest — create-only CAS", () => {
  it("publishes the request with baseHash null (create-only)", async () => {
    const { session } = await publishedRequest()
    expect(pushSpy).toHaveBeenCalledTimes(1)
    expect(pushSpy.mock.calls[0][0]).toBe(defaultSpaceLayout.joinSessionPush(session.code))
    expect(pushSpy.mock.calls[0][2]).toBeNull()
    expect(slotOf(session.code)?.data.phase).toBe("request")
  })

  it("conflicts when a second party tries to create at the same code's slot", async () => {
    const { session } = await publishedRequest()
    const attacker = startSpaceJoinRequest({ origin: "https://evil.example", rendezvous: RENDEZVOUS })
    // Force the attacker onto the victim's slot: its own first publish is
    // create-only too, so an occupied slot must reject it.
    const client = fakeClient()
    await expect(
      client.push(defaultSpaceLayout.joinSessionPush(session.code), attacker.request as never, null),
    ).rejects.toBeInstanceOf(ConflictError)
    // The victim's document is untouched.
    expect(slotOf(session.code)?.data.origin).toBe(ORIGIN)
  })

  it("re-publishes against its OWN remembered hash, not whatever is at the slot", async () => {
    const { session } = await publishedRequest()
    await session.publish()
    expect(pushSpy.mock.calls[1][2]).toBe("h1")
  })

  it("surfaces a conflict when the slot was overwritten between two publishes", async () => {
    const { session } = await publishedRequest()
    // A third party overwrites with the current hash — the session does not know.
    const client = fakeClient()
    await client.push(defaultSpaceLayout.joinSessionPush(session.code), { v: 1, phase: "request" }, "h1")
    await expect(session.publish()).rejects.toBeInstanceOf(ConflictError)
  })
})

// ── PoP signature ─────────────────────────────────────────────────────────────

describe("parseSpaceJoinRequest — proof-of-possession", () => {
  it("rejects a tampered devEdPub", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    const tampered = { ...request, devEdPub: generateDeviceKeys().edPub }
    expect(() => parseSpaceJoinRequest(JSON.stringify(tampered), code)).toThrow(
      /invalid proof-of-possession signature/,
    )
  })

  it("rejects a tampered devKemPub (key-substitution / MITM)", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    const tampered = { ...request, devKemPub: generateDeviceKeys().kemPub }
    expect(() => parseSpaceJoinRequest(JSON.stringify(tampered), code)).toThrow(
      /invalid proof-of-possession signature/,
    )
  })

  it("rejects the document when read from a DIFFERENT code's slot (relocation)", () => {
    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    const otherCode = createSpaceJoinRequest({ origin: ORIGIN }).code
    expect(() => parseSpaceJoinRequest(JSON.stringify(request), otherCode)).toThrow(
      /invalid proof-of-possession signature/,
    )
  })

  it("rejects a request whose phase is not 'request'", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    expect(() => parseSpaceJoinRequest(JSON.stringify({ ...request, phase: "grant" }), code)).toThrow(
      /not a space join request payload/,
    )
  })

  it("rejects an over-long hex field before verifying anything", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    const tampered = { ...request, devEdPub: "a".repeat(1_000_000) }
    expect(() => parseSpaceJoinRequest(JSON.stringify(tampered), code)).toThrow(/devEdPub is not a valid/)
  })
})

// ── Bidi / control-character rejection ────────────────────────────────────────

describe("parseSpaceJoinRequest — origin/label sanitisation", () => {
  // Written as \u escapes, never literal control/bidi characters in source —
  // an invisible character in a test fixture is unreviewable in a diff.
  const RLO = "\u202E" // right-to-left override
  const LRI = "\u2066" // left-to-right isolate
  const DEL = "\u007F" // C0 delete
  const CSI = "\u009B" // C1 control sequence introducer

  function signedWith(fields: Partial<SpaceJoinRequestPayload>) {
    // origin/label are NOT covered by popSig (only the keys and the code are),
    // so an attacker can freely rewrite them on a valid document — which is
    // exactly why they get their own validation.
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN, label: "ok" })
    return { payload: JSON.stringify({ ...request, ...fields }), code }
  }

  it("rejects a bidi override in origin", () => {
    const { payload, code } = signedWith({ origin: `https://good.example${RLO}moc.live//:sptth` })
    expect(() => parseSpaceJoinRequest(payload, code)).toThrow(/control or bidi-override/)
  })

  it("rejects a bidi isolate in label", () => {
    const { payload, code } = signedWith({ label: `Safe${LRI} App` })
    expect(() => parseSpaceJoinRequest(payload, code)).toThrow(/control or bidi-override/)
  })

  it("rejects an embedded newline in label (fake app chrome)", () => {
    const { payload, code } = signedWith({ label: "Trusted\nVerified by OctoBot" })
    expect(() => parseSpaceJoinRequest(payload, code)).toThrow(/control or bidi-override/)
  })

  it("rejects a DEL / C1 control character in origin", () => {
    const { payload, code } = signedWith({ origin: `https://good.example/${DEL}${CSI}` })
    expect(() => parseSpaceJoinRequest(payload, code)).toThrow(/control or bidi-override/)
  })

  it("rejects an over-long origin and an over-long label", () => {
    const long = signedWith({ origin: `https://x.example/${"a".repeat(3000)}` })
    expect(() => parseSpaceJoinRequest(long.payload, long.code)).toThrow(/origin exceeds max length/)
    const longLabel = signedWith({ label: "l".repeat(500) })
    expect(() => parseSpaceJoinRequest(longLabel.payload, longLabel.code)).toThrow(/label exceeds max length/)
  })

  it("rejects an origin that is not a URL", () => {
    const { payload, code } = signedWith({ origin: "not a url" })
    expect(() => parseSpaceJoinRequest(payload, code)).toThrow(/origin is not a valid URL/)
  })

  it("accepts an ordinary origin and label", () => {
    const { payload, code } = signedWith({ origin: "https://good.example", label: "Good App" })
    expect(() => parseSpaceJoinRequest(payload, code)).not.toThrow()
  })
})

// ── Wall-clock-anchored TTL cap ───────────────────────────────────────────────

describe("parseSpaceJoinRequest — TTL enforcement", () => {
  it("rejects an already-expired request", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN, ttlSec: -60 })
    expect(() => parseSpaceJoinRequest(JSON.stringify(request), code)).toThrow(/expired/)
  })

  it("fails closed on a malformed expiresAt instead of treating it as fresh", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    const tampered = { ...request, expiresAt: "whenever" }
    expect(() => parseSpaceJoinRequest(JSON.stringify(tampered), code)).toThrow(/expired/)
  })

  it("rejects a far-future window that stays inside the cap RELATIVE TO createdAt", () => {
    // The anti-bypass case: expiresAt - createdAt is only one hour, so a
    // createdAt-relative check would pass — but the code would stay live for a
    // year. The cap is anchored to the real wall clock, so this must fail.
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN })
    const farFuture = Date.now() + 364 * 24 * 60 * 60 * 1000
    const tampered = {
      ...request,
      createdAt: new Date(farFuture).toISOString(),
      expiresAt: new Date(farFuture + 60 * 60 * 1000).toISOString(),
    }
    expect(() => parseSpaceJoinRequest(JSON.stringify(tampered), code)).toThrow(
      /expiry window exceeds the maximum/,
    )
  })

  it("accepts a window just inside the cap", () => {
    const { request, code } = createSpaceJoinRequest({ origin: ORIGIN, ttlSec: 59 * 60 })
    expect(() => parseSpaceJoinRequest(JSON.stringify(request), code)).not.toThrow()
  })
})

// ── fetchSpaceJoinRequestByCode ───────────────────────────────────────────────

describe("fetchSpaceJoinRequestByCode", () => {
  it("returns the parsed request plus the slot hash the grant write needs", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    expect(found?.request.origin).toBe(ORIGIN)
    expect(found?.hash).toBe(slotOf(session.code)?.hash)
  })

  it("returns null for an unknown code", async () => {
    const found = await fetchSpaceJoinRequestByCode({ code: "ZZZZ9999", rendezvous: RENDEZVOUS })
    expect(found).toBeNull()
  })

  it("returns null once the slot has advanced to the grant phase", async () => {
    const { session } = await approvedSession()
    expect(await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })).toBeNull()
  })

  it("throws (does not return null) for a present-but-expired request", async () => {
    const session = startSpaceJoinRequest({ origin: ORIGIN, rendezvous: RENDEZVOUS, ttlSec: -60 })
    await session.publish()
    await expect(
      fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS }),
    ).rejects.toThrow(/expired/)
  })

  it("propagates a transient server error instead of reporting 'wrong code'", async () => {
    const { session } = await publishedRequest()
    pullFailures = 1
    await expect(
      fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS }),
    ).rejects.toBeInstanceOf(StarfishHttpError)
  })
})

// ── Grant publish: CAS UPDATE, not create ─────────────────────────────────────

describe("publishSpaceJoinGrant — CAS update", () => {
  it("updates the SAME slot in place, presenting the request document's hash", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    const requestHash = found!.hash
    await publishSpaceJoinGrant({
      code: session.code,
      request: found!.request,
      sealer: makeSealer(),
      grant: GRANT,
      rendezvous: RENDEZVOUS,
      baseHash: requestHash,
    })
    const grantPush = pushSpy.mock.calls.at(-1)!
    expect(grantPush[0]).toBe(defaultSpaceLayout.joinSessionPush(session.code))
    expect(grantPush[2]).toBe(requestHash)
    expect(store.size).toBe(1)
    expect(slotOf(session.code)?.data.phase).toBe("grant")
  })

  it("refuses a create-shaped write (empty baseHash) up front", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    await expect(
      publishSpaceJoinGrant({
        code: session.code,
        request: found!.request,
        sealer: makeSealer(),
        grant: GRANT,
        rendezvous: RENDEZVOUS,
        baseHash: "",
      }),
    ).rejects.toThrow(/baseHash is required/)
    expect(slotOf(session.code)?.data.phase).toBe("request")
  })

  it("conflicts on a stale hash instead of silently overwriting a live grant", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    const staleHash = found!.hash
    await publishSpaceJoinGrant({
      code: session.code,
      request: found!.request,
      sealer: makeSealer(),
      grant: GRANT,
      rendezvous: RENDEZVOUS,
      baseHash: staleHash,
    })
    const liveHash = slotOf(session.code)!.hash
    await expect(
      publishSpaceJoinGrant({
        code: session.code,
        request: found!.request,
        sealer: makeSealer(),
        grant: { spaceId: "sp-overwritten", cap: {} },
        rendezvous: RENDEZVOUS,
        baseHash: staleHash,
      }),
    ).rejects.toBeInstanceOf(ConflictError)
    expect(slotOf(session.code)!.hash).toBe(liveHash)
  })

  it("makes a racing bogus grant a detectable conflict, not a silent bypass", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    // The attacker knows the code but not the slot's current hash.
    await expect(
      publishSpaceJoinGrant({
        code: session.code,
        request: found!.request,
        sealer: makeSealer(),
        grant: { spaceId: "sp-attacker", cap: {} },
        rendezvous: RENDEZVOUS,
        baseHash: "h-guessed",
      }),
    ).rejects.toBeInstanceOf(ConflictError)
    expect(slotOf(session.code)?.data.phase).toBe("request")
  })

  it("makes the honest approver's write fail when an attacker wins the race", async () => {
    const { session } = await publishedRequest()
    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    // Attacker lands first, using the same hash the approver holds.
    await publishSpaceJoinGrant({
      code: session.code,
      request: found!.request,
      sealer: makeSealer(),
      grant: { spaceId: "sp-attacker", cap: {} },
      rendezvous: RENDEZVOUS,
      baseHash: found!.hash,
    })
    await expect(
      publishSpaceJoinGrant({
        code: session.code,
        request: found!.request,
        sealer: makeSealer(),
        grant: GRANT,
        rendezvous: RENDEZVOUS,
        baseHash: found!.hash,
      }),
    ).rejects.toBeInstanceOf(ConflictError)
  })
})

// ── fetchSpaceJoinGrant ───────────────────────────────────────────────────────

describe("fetchSpaceJoinGrant", () => {
  it("returns null while the slot is still phase 'request'", async () => {
    const { session } = await publishedRequest()
    expect(await fetchSpaceJoinGrant(session)).toBeNull()
  })

  it("returns null when nothing has been published under the code at all", async () => {
    const session = startSpaceJoinRequest({ origin: ORIGIN, rendezvous: RENDEZVOUS })
    expect(await fetchSpaceJoinGrant(session)).toBeNull()
  })

  it("resolves {spaceId, cap, sealedBy} once the slot flips to phase 'grant'", async () => {
    const { session, sealer } = await approvedSession()
    const grant = await fetchSpaceJoinGrant(session)
    expect(grant).toEqual({ spaceId: GRANT.spaceId, cap: GRANT.cap, sealedBy: sealer.edPubHex })
  })

  it("does not read any space content — the credential is all it returns", async () => {
    const { session } = await approvedSession()
    const grant = await fetchSpaceJoinGrant(session)
    expect(Object.keys(grant!).sort()).toEqual(["cap", "sealedBy", "spaceId"])
  })

  it("stays re-pollable: a successful read does NOT clear the slot", async () => {
    const { session } = await approvedSession()
    expect(await fetchSpaceJoinGrant(session)).not.toBeNull()
    expect(await fetchSpaceJoinGrant(session)).not.toBeNull()
    expect(slotOf(session.code)?.data.phase).toBe("grant")
  })

  it("keeps the grant unreadable to anyone without the requester's KEM private key", async () => {
    const { session } = await approvedSession()
    const eavesdropper = { ...session, device: generateDeviceKeys() }
    await expect(fetchSpaceJoinGrant(eavesdropper)).rejects.toThrow()
    // The plaintext never appears in the public document.
    expect(JSON.stringify(slotOf(session.code)?.data)).not.toContain(GRANT.spaceId)
  })

  it("rejects a malformed sealed blob rather than returning a half-built grant", async () => {
    const { session } = await approvedSession()
    const slot = slotOf(session.code)!
    slot.data = { ...slot.data, sealed: "not-a-blob" }
    await expect(fetchSpaceJoinGrant(session)).rejects.toThrow(/malformed sealed blob/)
    await expect(fetchSpaceJoinGrant(session)).rejects.toBeInstanceOf(SpaceJoinGrantIntegrityError)
  })

  it("rejects an envelope with an explicit null cap, not just a missing one", async () => {
    // Regression pin: the Python twin rejects `cap: null` as malformed
    // (`envelope.get("cap") is None`); this side must match, not silently
    // accept `cap === null` as if it were an empty-but-valid grant.
    const { session, sealer } = await approvedSession()
    await publishSpaceJoinGrant({
      code: session.code,
      request: session.request,
      sealer,
      grant: { spaceId: "sp-null-cap", cap: null },
      rendezvous: RENDEZVOUS,
      baseHash: slotOf(session.code)!.hash,
    })
    await expect(fetchSpaceJoinGrant(session)).rejects.toThrow(/malformed grant envelope/)
    await expect(fetchSpaceJoinGrant(session)).rejects.toBeInstanceOf(SpaceJoinGrantIntegrityError)
  })

  it("wraps an unseal failure (wrong AAD/recipient/sealer) as an integrity error too", async () => {
    const { session } = await approvedSession()
    const eavesdropper = { ...session, device: generateDeviceKeys() }
    await expect(fetchSpaceJoinGrant(eavesdropper)).rejects.toBeInstanceOf(SpaceJoinGrantIntegrityError)
  })
})

// ── Seal AAD = code (anti-relocation) ─────────────────────────────────────────

describe("fetchSpaceJoinGrant — AAD is the code", () => {
  it("fails to unseal a grant ciphertext copied into a DIFFERENT code's slot", async () => {
    const { session } = await approvedSession()
    const grantDoc = slotOf(session.code)!.data

    // Same requester, same KEM private key, same sealer — only the slot moved.
    const otherSession = startSpaceJoinRequest({ origin: ORIGIN, rendezvous: RENDEZVOUS })
    store.set(docKey(defaultSpaceLayout.joinSessionPull(otherSession.code)), {
      data: grantDoc,
      hash: "relocated",
    })

    const relocated = { ...otherSession, device: session.device }
    // Sanity: the copy IS readable at its original address — so the failure
    // below is the AAD binding, not a broken fixture.
    expect(await fetchSpaceJoinGrant(session)).not.toBeNull()
    await expect(fetchSpaceJoinGrant(relocated)).rejects.toThrow()
  })
})

// ── TOFU sealer pinning ───────────────────────────────────────────────────────

describe("fetchSpaceJoinGrant — expectedSealer pinning", () => {
  it("accepts a grant sealed by the pinned identity", async () => {
    const { session, sealer } = await approvedSession()
    const grant = await fetchSpaceJoinGrant(session, { expectedSealer: sealer.edPubHex })
    expect(grant?.spaceId).toBe(GRANT.spaceId)
  })

  it("rejects a grant re-sealed by a different identity at the same slot", async () => {
    const { session, sealer } = await approvedSession()
    const pinned = sealer.edPubHex

    // A second writer replaces the established grant with its own, correctly
    // CAS'd (it observed the current hash) and sealed to the same requester —
    // undetectable at the transport layer, caught only by the TOFU pin.
    const found = slotOf(session.code)!
    await publishSpaceJoinGrant({
      code: session.code,
      request: session.request,
      sealer: makeSealer(),
      grant: { spaceId: "sp-impostor", cap: {} },
      rendezvous: RENDEZVOUS,
      baseHash: found.hash,
    })

    // Without the pin it silently succeeds with the impostor's space…
    expect((await fetchSpaceJoinGrant(session))?.spaceId).toBe("sp-impostor")
    // …with the pin it is refused.
    await expect(fetchSpaceJoinGrant(session, { expectedSealer: pinned })).rejects.toThrow(
      /not signed by the required sealer/,
    )
  })
})

// ── clearSpaceJoinGrant ───────────────────────────────────────────────────────

describe("clearSpaceJoinGrant", () => {
  it("empties the slot so the code stops resolving to a usable grant", async () => {
    const { session } = await approvedSession()
    await clearSpaceJoinGrant({ code: session.code, rendezvous: RENDEZVOUS })
    expect(slotOf(session.code)?.data).toEqual({})
    expect(await fetchSpaceJoinGrant(session)).toBeNull()
  })

  it("is idempotent — clearing an already-cleared slot still succeeds", async () => {
    const { session } = await approvedSession()
    await clearSpaceJoinGrant({ code: session.code, rendezvous: RENDEZVOUS })
    await expect(clearSpaceJoinGrant({ code: session.code, rendezvous: RENDEZVOUS })).resolves.toBeDefined()
  })

  it("succeeds on a code that was never published — a 404 pull is not an error", async () => {
    // Regression pin: clearSpaceJoinGrant's own docstring claims cleanup must
    // succeed even without a remembered hash; a code the requester generated
    // and displayed but never actually published (cancelled before publish(),
    // or TTL-reclaimed) must clear cleanly rather than crashing on the pull.
    const code = "NEVERPUB"
    expect(slotOf(code)).toBeUndefined()
    await expect(clearSpaceJoinGrant({ code, rendezvous: RENDEZVOUS })).resolves.toBeDefined()
    expect(slotOf(code)?.data).toEqual({})
  })

  it("retries through transient conflicts and eventually surfaces the raw ConflictError", async () => {
    // Regression pin: clearSpaceJoinGrant now goes through the shared runCas
    // helper (5 attempts, jittered backoff) instead of a bespoke 3-attempt
    // loop, and lets the real ConflictError propagate rather than wrapping it
    // in a bespoke "too many baseHash conflicts" Error.
    vi.useFakeTimers()
    const { session } = await approvedSession()
    pushConflicts = 10 // more than runCas's MAX_ATTEMPTS will ever retry through
    const result = clearSpaceJoinGrant({ code: session.code, rendezvous: RENDEZVOUS })
    result.catch(() => {}) // avoid an unhandled-rejection warning while timers advance
    await vi.advanceTimersByTimeAsync(10_000)
    await expect(result).rejects.toBeInstanceOf(ConflictError)
  })

  it("is never invoked automatically by a successful fetch", async () => {
    const { session } = await approvedSession()
    const pushesBefore = pushSpy.mock.calls.length
    await fetchSpaceJoinGrant(session)
    expect(pushSpy.mock.calls.length).toBe(pushesBefore)
  })

  it("permanently retires the code — a fresh create-only publish afterwards conflicts", async () => {
    // Clearing overwrites the slot with `{}` rather than deleting it, so the
    // slot is no longer "unwritten" — matches the module's own claim that
    // clearing "stops the CODE from resolving to a usable grant again", not
    // that it frees the code for reuse. Codes are always freshly random
    // (~39.6 bits), so this never matters in practice, but a regression here
    // (e.g. clear switching to a real delete) would silently change what a
    // stale/replayed code can do, so it is worth pinning.
    const { session } = await approvedSession()
    const code = session.code
    await clearSpaceJoinGrant({ code, rendezvous: RENDEZVOUS })

    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    const { makeAnonSpaceClient } = await import("../src/client.js")
    const client = makeAnonSpaceClient(RENDEZVOUS)
    await expect(
      client.push(defaultSpaceLayout.joinSessionPush(code), request as unknown as Record<string, unknown>, null),
    ).rejects.toBeInstanceOf(ConflictError)
  })
})

// ── Independent sessions ─────────────────────────────────────────────────────

describe("two independent codes", () => {
  it("do not interfere with each other's slot", async () => {
    const a = await approvedSession()
    const b = await approvedSession()
    expect(a.session.code).not.toBe(b.session.code)

    const grantA = await fetchSpaceJoinGrant(a.session)
    const grantB = await fetchSpaceJoinGrant(b.session)
    expect(grantA?.sealedBy).toBe(a.sealer.edPubHex)
    expect(grantB?.sealedBy).toBe(b.sealer.edPubHex)

    // Clearing one code's slot must not touch the other.
    await clearSpaceJoinGrant({ code: a.session.code, rendezvous: RENDEZVOUS })
    expect(await fetchSpaceJoinGrant(a.session)).toBeNull()
    const stillThere = await fetchSpaceJoinGrant(b.session)
    expect(stillThere?.sealedBy).toBe(b.sealer.edPubHex)
  })
})

// ── awaitSpaceJoinGrant ───────────────────────────────────────────────────────

describe("awaitSpaceJoinGrant", () => {
  it("times out while the slot is still a pending request", async () => {
    const { session } = await publishedRequest()
    await expect(awaitSpaceJoinGrant(session, { timeoutMs: 0 })).rejects.toThrow(
      /timed out waiting for the space join to be approved/,
    )
  })

  it("reports the last transient error rather than a bare timeout", async () => {
    const { session } = await publishedRequest()
    pullFailures = 1
    await expect(awaitSpaceJoinGrant(session, { timeoutMs: 0 })).rejects.toBeInstanceOf(StarfishHttpError)
  })

  it("returns immediately when the grant is already published", async () => {
    const { session } = await approvedSession()
    await expect(awaitSpaceJoinGrant(session, { timeoutMs: 0 })).resolves.toMatchObject({
      spaceId: GRANT.spaceId,
    })
  })

  it("retries past transient errors and resolves once a poll succeeds", async () => {
    const { session } = await approvedSession()
    pullFailures = 2
    vi.useFakeTimers()
    const pending = awaitSpaceJoinGrant(session, { timeoutMs: 60_000 })
    await vi.advanceTimersByTimeAsync(10_000)
    await expect(pending).resolves.toMatchObject({ spaceId: GRANT.spaceId })
    expect(pullFailures).toBe(0)
  })

  it("rejects immediately on an already-aborted signal", async () => {
    const { session } = await publishedRequest()
    await expect(
      awaitSpaceJoinGrant(session, { signal: AbortSignal.abort(), timeoutMs: 60_000 }),
    ).rejects.toThrow(/aborted/)
  })

  it("forwards expectedSealer to every poll", async () => {
    const { session } = await approvedSession()
    await expect(
      awaitSpaceJoinGrant(session, { timeoutMs: 0, expectedSealer: generateDeviceKeys().edPub }),
    ).rejects.toThrow(/not signed by the required sealer/)
  })

  it("fails fast on a forged grant instead of polling it all the way to the timeout", async () => {
    // Regression pin: a SpaceJoinGrantIntegrityError must reject on the very
    // FIRST attempt, not after retrying to the deadline. Proven here by never
    // calling vi.advanceTimersByTimeAsync at all — if this fell through to
    // the generic swallow-and-retry path, the pending promise would hang
    // forever under fake timers instead of settling.
    const { session, sealer } = await approvedSession()
    await publishSpaceJoinGrant({
      code: session.code,
      request: session.request,
      sealer,
      grant: { spaceId: "sp-null-cap", cap: null },
      rendezvous: RENDEZVOUS,
      baseHash: slotOf(session.code)!.hash,
    })
    vi.useFakeTimers()
    const pending = awaitSpaceJoinGrant(session, { timeoutMs: 60_000 })
    await expect(pending).rejects.toBeInstanceOf(SpaceJoinGrantIntegrityError)
  })
})

// ── joinRequestFromSpaceJoinRequest ───────────────────────────────────────────

describe("joinRequestFromSpaceJoinRequest", () => {
  it("rebuilds the {edPub, kemPub, userId, kemSig} shape inviteToSpace expects", async () => {
    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    const parsed = JSON.parse(await joinRequestFromSpaceJoinRequest(request)) as Record<string, string>
    expect(Object.keys(parsed).sort()).toEqual(["edPub", "kemPub", "kemSig", "userId"])
    expect(parsed.edPub).toBe(request.devEdPub)
    expect(parsed.kemPub).toBe(request.devKemPub)
    expect(parsed.userId).toBe(await defaultUserIdFromEdPub(request.devEdPub))
    // The two checks parseJoinRequest performs on the approving side.
    expect(verifyKemSig(parsed.edPub, parsed.kemPub, parsed.kemSig)).toBe(true)
  })

  it("derives userId with a passed-in override instead of the global default", async () => {
    // A regression pin: an approver whose Session was built with a custom
    // userIdFromEdPub must be able to get a matching userId here, or
    // inviteToSpace's parseJoinRequest (which always uses the session's own
    // hook) rejects every join with "userId does not match edPub".
    const { request } = createSpaceJoinRequest({ origin: ORIGIN })
    const customUserIdFromEdPub = async (edPub: string) => `custom:${edPub}`
    const parsed = JSON.parse(
      await joinRequestFromSpaceJoinRequest(request, customUserIdFromEdPub),
    ) as Record<string, string>
    expect(parsed.userId).toBe(`custom:${request.devEdPub}`)
    expect(parsed.userId).not.toBe(await defaultUserIdFromEdPub(request.devEdPub))
  })
})

// ── End-to-end ────────────────────────────────────────────────────────────────

describe("end-to-end, one slot", () => {
  it("runs request → approve → grant entirely within a single document", async () => {
    const session = startSpaceJoinRequest({ origin: ORIGIN, label: "Demo", rendezvous: RENDEZVOUS })
    await session.publish()

    const found = await fetchSpaceJoinRequestByCode({ code: session.code, rendezvous: RENDEZVOUS })
    expect(found!.request.label).toBe("Demo")
    const joinRequestJson = await joinRequestFromSpaceJoinRequest(found!.request)
    expect(JSON.parse(joinRequestJson).edPub).toBe(session.device.edPub)

    const sealer = makeSealer()
    await publishSpaceJoinGrant({
      code: session.code,
      request: found!.request,
      sealer,
      grant: GRANT,
      rendezvous: RENDEZVOUS,
      baseHash: found!.hash,
    })

    const grant = await awaitSpaceJoinGrant(session, { timeoutMs: 0 })
    expect(grant).toEqual({ spaceId: GRANT.spaceId, cap: GRANT.cap, sealedBy: sealer.edPubHex })
    // Exactly one document existed for the whole exchange.
    expect(store.size).toBe(1)
  })
})
