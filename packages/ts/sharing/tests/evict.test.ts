import { describe, it, expect, beforeAll, vi } from "vitest"
import { configurePlatform, getBase64, revocationListCanonicalSigningInput } from "@drakkar.software/starfish-protocol"
import { x25519, ed25519 } from "@noble/curves/ed25519.js"
import { createKeyring, keyringPathFor, type Keyring } from "@drakkar.software/starfish-keyring"
import { StarfishHttpError, type StarfishClient } from "@drakkar.software/starfish-client"
import { evictMember } from "../src/evict.js"
import { membersPathFor } from "../src/directory.js"

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

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}
function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substring(i * 2, i * 2 + 2), 16)
  return out
}
function makeParty() {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPriv: hex(edPriv),
    edPub: hex(ed25519.getPublicKey(edPriv)),
    kemPriv: hex(kemPriv),
    kemPub: hex(x25519.getPublicKey(kemPriv)),
  }
}
function edVerify(pubHex: string, sigB64: string, message: string): boolean {
  return ed25519.verify(getBase64().decode(sigB64), new TextEncoder().encode(message), hexToBytes(pubHex))
}

/** In-memory fake client keyed by request path; mirrors pushes back onto the pull path. */
function makeClient(initial: Record<string, unknown>) {
  const store = new Map<string, { data: unknown; hash: string }>()
  for (const [k, v] of Object.entries(initial)) store.set(`/pull/${k}`, { data: v, hash: "h0" })
  let n = 0
  const client = {
    pull: vi.fn(async (path: string) => {
      const entry = store.get(path)
      if (!entry) throw new StarfishHttpError(404, "not found")
      return { data: entry.data as Record<string, unknown>, hash: entry.hash, timestamp: 1000 }
    }),
    push: vi.fn(async (path: string, data: Record<string, unknown>) => {
      n += 1
      store.set(path.replace("/push/", "/pull/"), { data, hash: `h${n}` })
      return { hash: `h${n}`, timestamp: 2000 }
    }),
  } as unknown as StarfishClient
  return { client, store }
}

const NONCE = getBase64().encode(new Uint8Array(16).fill(0x11))
const MEMBER_SUB = "cd".repeat(32)

describe("evictMember", () => {
  it("is a no-op when both flags are false", async () => {
    const owner = makeParty()
    const member = makeParty()
    const { client } = makeClient({})
    const submitRevocation = vi.fn(async () => {})

    const result = await evictMember(
      client,
      {
        keyringCollection: "room",
        membersCollection: "room",
        member: { sub: MEMBER_SUB, nonce: NONCE, exp: 1999999999, subKem: member.kemPub },
        adder: { edPriv: owner.edPriv, edPub: owner.edPub, kemPriv: owner.kemPriv },
        trustedAdders: [owner.edPub],
        issEdPubHex: owner.edPub,
        issEdPrivHex: owner.edPriv,
        generation: 1,
        submitRevocation,
      },
      { rotate: false, revoke: false },
    )

    expect(result).toEqual({ revoked: false })
    expect(submitRevocation).not.toHaveBeenCalled()
    expect((client.push as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled()
  })

  it("rotates the keyring, submits a verifying revocation list, and de-rosters", async () => {
    const owner = makeParty()
    const member = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPriv, edPubHex: owner.edPub },
      [{ subKemHex: owner.kemPub }, { subKemHex: member.kemPub }],
    )
    const directory = { v: 1, entries: [{ nonce: NONCE, subUserId: "deadbeef", sub: MEMBER_SUB }] }
    const { client, store } = makeClient({
      [keyringPathFor("room")]: keyring,
      [membersPathFor("room")]: directory,
    })

    const submitted: Array<Record<string, unknown>> = []
    const prior = [{ sub: "ab".repeat(32), nonce: getBase64().encode(new Uint8Array(16).fill(0x22)), exp: 1999999999 }]

    const result = await evictMember(
      client,
      {
        keyringCollection: "room",
        membersCollection: "room",
        member: { sub: MEMBER_SUB, nonce: NONCE, exp: 1999999999, subKem: member.kemPub },
        adder: { edPriv: owner.edPriv, edPub: owner.edPub, kemPriv: owner.kemPriv },
        trustedAdders: [owner.edPub],
        issEdPubHex: owner.edPub,
        issEdPrivHex: owner.edPriv,
        generation: 7,
        priorRevoked: prior,
        submitRevocation: async (l) => {
          submitted.push(l as unknown as Record<string, unknown>)
        },
      },
      { rotate: true, revoke: true },
    )

    // (a) rotated → new epoch
    expect(result.newEpoch).toBe(2)
    expect(result.revoked).toBe(true)

    // (b) one signed list, verifies, names prior + member
    expect(submitted).toHaveLength(1)
    const list = submitted[0]! as { generation: number; issUserId: string; sig: string; revoked: Array<{ sub: string; nonce: string }> }
    expect(list.generation).toBe(7)
    expect(list.issUserId).toHaveLength(32)
    expect(edVerify(owner.edPub, list.sig, revocationListCanonicalSigningInput(list as never))).toBe(true)
    const pairs = new Set(list.revoked.map((e) => `${e.sub}|${e.nonce}`))
    expect(pairs.has(`${MEMBER_SUB}|${NONCE}`)).toBe(true)
    expect(pairs.has(`${prior[0]!.sub}|${prior[0]!.nonce}`)).toBe(true)

    // (c) directory entry gone; (d) dropped recipient absent from rotated epoch
    const dir = store.get(`/pull/${membersPathFor("room")}`)!.data as { entries: Array<{ nonce: string }> }
    expect(dir.entries.some((e) => e.nonce === NONCE)).toBe(false)
    const rotated = store.get(`/pull/${keyringPathFor("room")}`)!.data as Keyring
    expect(rotated.epochs["2"]!.wrappedKeys.some((e) => e.subKem === member.kemPub)).toBe(false)
  })

  it("revoke-only (no keyring params) revokes the cap and drops the roster entry", async () => {
    const owner = makeParty()
    const member = makeParty()
    const directory = { v: 1, entries: [{ nonce: NONCE, subUserId: "deadbeef", sub: MEMBER_SUB }] }
    const { client, store } = makeClient({ [membersPathFor("board")]: directory })

    const submitted: Array<Record<string, unknown>> = []
    const result = await evictMember(
      client,
      {
        membersCollection: "board",
        member: { sub: MEMBER_SUB, nonce: NONCE, exp: 1999999999, subKem: member.kemPub },
        issEdPubHex: owner.edPub,
        issEdPrivHex: owner.edPriv,
        generation: 3,
        submitRevocation: async (l) => {
          submitted.push(l as unknown as Record<string, unknown>)
        },
      },
      { rotate: false, revoke: true },
    )

    expect(result.revoked).toBe(true)
    expect(result.newEpoch).toBeUndefined()
    expect(submitted).toHaveLength(1)
    const dir = store.get(`/pull/${membersPathFor("board")}`)!.data as { entries: Array<{ nonce: string }> }
    expect(dir.entries.some((e) => e.nonce === NONCE)).toBe(false)
  })

  it("rotate=true without keyring params throws (the footgun is caught)", async () => {
    const owner = makeParty()
    const member = makeParty()
    const { client } = makeClient({})
    await expect(
      evictMember(
        client,
        {
          membersCollection: "board",
          member: { sub: MEMBER_SUB, nonce: NONCE, exp: 1999999999, subKem: member.kemPub },
          issEdPubHex: owner.edPub,
          issEdPrivHex: owner.edPriv,
          generation: 1,
          submitRevocation: async () => {},
        },
        { rotate: true, revoke: false },
      ),
    ).rejects.toThrow(/requires keyringCollection/)
  })
})
