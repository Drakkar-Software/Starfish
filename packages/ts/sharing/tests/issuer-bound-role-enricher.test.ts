import { describe, it, expect } from "vitest"
import type { AuthResult } from "@drakkar.software/starfish-server"
import { makeIssuerBoundRoleEnricher } from "../src/issuer-bound-role-enricher.js"

const OWNER = "pubspace:owner"
const READER = "pubspace:reader"
const WRITER = "pubspace:writer"

function makeEnricher() {
  return makeIssuerBoundRoleEnricher({
    ownerParam: "ownerId",
    ownerRole: OWNER,
    readerRole: READER,
    writerRole: WRITER,
    collections: ["pubspace", "pubstream"],
    guardParam: "docId",
    guardValue: "_rooms",
  })
}

function auth(identity: string, roles: string[]): AuthResult {
  return { identity, roles }
}

describe("makeIssuerBoundRoleEnricher", () => {
  it("owner gets owner and reader", async () => {
    expect(
      await makeEnricher()(auth("alice", []), { ownerId: "alice", docId: "room-1" }),
    ).toEqual([OWNER, READER])
  })

  it("delegated by owner gets reader", async () => {
    expect(
      await makeEnricher()(auth("bob", ["delegated:alice:pubspace"]), {
        ownerId: "alice",
        docId: "room-1",
      }),
    ).toEqual([READER])
  })

  it("delegated + cap:write on non-guard doc gets writer", async () => {
    expect(
      await makeEnricher()(auth("bob", ["delegated:alice:pubspace", "cap:write:pubspace"]), {
        ownerId: "alice",
        docId: "room-1",
      }),
    ).toEqual([READER, WRITER])
  })

  it("delegated + cap:write on guard doc gets NO writer", async () => {
    expect(
      await makeEnricher()(auth("bob", ["delegated:alice:pubspace", "cap:write:pubspace"]), {
        ownerId: "alice",
        docId: "_rooms",
      }),
    ).toEqual([READER])
  })

  it("unrelated issuer gets nothing", async () => {
    expect(
      await makeEnricher()(auth("bob", ["delegated:carol:pubspace", "cap:write:pubspace"]), {
        ownerId: "alice",
        docId: "room-1",
      }),
    ).toEqual([])
  })

  it("alt collection delegation admitted", async () => {
    expect(
      await makeEnricher()(auth("bob", ["delegated:alice:pubstream", "cap:write:pubstream"]), {
        ownerId: "alice",
        docId: "room-1",
      }),
    ).toEqual([READER, WRITER])
  })

  it("missing owner param", async () => {
    expect(await makeEnricher()(auth("alice", []), { docId: "room-1" })).toEqual([])
  })

  it("empty identity", async () => {
    expect(
      await makeEnricher()(auth("", []), { ownerId: "alice", docId: "room-1" }),
    ).toEqual([])
  })
})
