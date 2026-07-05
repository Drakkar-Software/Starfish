/**
 * Tests for appendToInbox — the extracted public inbox-append helper.
 * Mocks makeAnonSpaceClient so the test verifies the orchestration: an anon client
 * appendAnonymous to the session-layout inbox push path, authored by session keys.
 */
import { describe, it, expect, vi } from "vitest"

const appendSpy = vi.fn(async () => ({}))
vi.mock("../src/client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client.js")>()
  return { ...actual, makeAnonSpaceClient: vi.fn(() => ({ appendAnonymous: appendSpy })) }
})

import { appendToInbox } from "../src/inbox.js"
import { makeAnonSpaceClient } from "../src/client.js"
import type { Session } from "../src/session.js"

function makeSession(): Session {
  return {
    userId: "owner",
    baseUrl: "https://sync.test",
    namespace: "ns",
    keys: { edPub: "edpub", edPriv: "edpriv", kemPub: "kempub", kemPriv: "kempriv" },
    layout: { inboxPush: (id: string, shard?: string) => `/push/inbox/${id}/${shard}` },
  } as unknown as Session
}

describe("appendToInbox", () => {
  it("appends via an anon client to the inbox push path, authored by the session keys", async () => {
    appendSpy.mockClear()
    const el = { sealed: { x: 1 }, ts: 123 }
    await appendToInbox(makeSession(), "recipient", "2026-07", el)
    expect(makeAnonSpaceClient).toHaveBeenCalledWith({ baseUrl: "https://sync.test", namespace: "ns" })
    expect(appendSpy).toHaveBeenCalledWith(
      "/push/inbox/recipient/2026-07",
      el,
      { edPubHex: "edpub", edPrivHex: "edpriv" },
    )
  })
})
