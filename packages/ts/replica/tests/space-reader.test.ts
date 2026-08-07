/**
 * Tests for `readSpaceMirror` — the session-less read side of a space
 * mirror. Drives a real `StarfishClient` against a mocked `fetch`, matching
 * `packages/ts/spaces/tests/registry.test.ts`'s idiom for testing code that
 * builds its own `StarfishClient` internally (rather than a Map-backed fake
 * `pull`/`push` pair, which only fits code that receives a client instance).
 */
import { describe, expect, it, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import type { CapCert } from "@drakkar.software/starfish-protocol"
import { x25519, ed25519 } from "@noble/curves/ed25519.js"
import { createKeyring, createKeyringEncryptor } from "@drakkar.software/starfish-keyring"
import { readSpaceMirror, readPublicSpaceMirror } from "../src/space/reader.js"

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

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })
}

const SPACE_ID = "sp-test"
const docPath = (_collectionId: string, spaceId: string, nodeId: string) =>
  `spaces/${spaceId}/objects/mirror/${nodeId}`
const isKnown = (type: string) => type === "a" || type === "b"

describe("readSpaceMirror", () => {
  it("returns {} without pulling the keyring when no node in the tree is recognized", async () => {
    const dev = makeParty()
    const fetchMock = async (url: string) => {
      if (url.includes("objects/_index")) {
        return jsonResponse({ data: { objects: [{ id: "n1", type: "unrelated" }] }, hash: "h1", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }
    let calls = 0
    const counted = async (url: string) => {
      calls++
      return fetchMock(url)
    }

    const result = await readSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      cap: { iss: "owner", subKem: dev.kemPub } as unknown as CapCert,
      devEdPrivHex: dev.edPriv,
      devKemPrivHex: dev.kemPriv,
      isKnownCollection: isKnown,
      docPath,
      fetch: counted as unknown as typeof fetch,
    })

    expect(result).toEqual({})
    expect(calls).toBe(1)
  })

  it("decrypts an encrypted node and passes through a plaintext one, ignoring unknown node types", async () => {
    const owner = makeParty()
    const dev = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPriv, edPubHex: owner.edPub },
      [{ subKemHex: dev.kemPub }],
    )
    const encryptor = await createKeyringEncryptor(
      keyring,
      { kemPubHex: dev.kemPub, kemPrivHex: dev.kemPriv },
      { trustedAdders: [owner.edPub] },
    )
    const sealed = await encryptor.encrypt({ hello: "world" })

    const fetchMock = async (url: string) => {
      if (url.includes("objects/_index")) {
        return jsonResponse({
          data: {
            objects: [
              { id: "node-a", type: "a" },
              { id: "node-b", type: "b" },
              { id: "node-unrelated", type: "unrelated" },
            ],
          },
          hash: "h1",
          timestamp: 1,
        })
      }
      if (url.includes("_keyring")) {
        return jsonResponse({ data: keyring, hash: "h2", timestamp: 1 })
      }
      if (url.includes(`objects/mirror/node-a`)) {
        return jsonResponse({ data: sealed, hash: "h3", timestamp: 1 })
      }
      if (url.includes(`objects/mirror/node-b`)) {
        return jsonResponse({ data: { plain: true }, hash: "h4", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      cap: { iss: owner.edPub, subKem: dev.kemPub } as unknown as CapCert,
      devEdPrivHex: dev.edPriv,
      devKemPrivHex: dev.kemPriv,
      isKnownCollection: isKnown,
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({ a: { hello: "world" }, b: { plain: true } })
    expect(result).not.toHaveProperty("unrelated")
  })

  it("throws a clear error when an encrypted node is present but the keyring doc has no epochs yet", async () => {
    const owner = makeParty()
    const dev = makeParty()
    const fetchMock = async (url: string) => {
      if (url.includes("objects/_index")) {
        return jsonResponse({ data: { objects: [{ id: "node-a", type: "a" }] }, hash: "h1", timestamp: 1 })
      }
      if (url.includes("_keyring")) {
        return jsonResponse({ data: {}, hash: "h2", timestamp: 1 })
      }
      // The node genuinely IS encrypted — which is what makes the missing
      // keyring a real failure rather than something the reader can skip.
      if (url.includes("objects/mirror/node-a")) {
        return jsonResponse({ data: { _encrypted: "deadbeef", _epoch: 0 }, hash: "h3", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    await expect(
      readSpaceMirror({
        rendezvous: { baseUrl: "https://h", namespace: "ns" },
        spaceId: SPACE_ID,
        cap: { iss: owner.edPub, subKem: dev.kemPub } as unknown as CapCert,
        devEdPrivHex: dev.edPriv,
        devKemPrivHex: dev.kemPriv,
        isKnownCollection: isKnown,
        docPath,
        fetch: fetchMock as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/no keyring yet/)
  })

  it("reads an all-public space without pulling the keyring at all", async () => {
    // The regression this guards: an all-public space never mints a keyring
    // (nothing in it was ever encrypted), so an unconditional keyring pull
    // threw on a space whose every node this reader can read as plaintext.
    const owner = makeParty()
    const dev = makeParty()
    let keyringPulls = 0
    const fetchMock = async (url: string) => {
      if (url.includes("_keyring")) {
        keyringPulls++
        // Exactly what the server has for a space that never encrypted
        // anything: no keyring doc, so no `epochs`.
        return jsonResponse({ data: {}, hash: "", timestamp: 1 })
      }
      if (url.includes("objects/_index")) {
        return jsonResponse({
          data: {
            objects: [
              { id: "node-a", type: "a" },
              { id: "node-b", type: "b" },
            ],
          },
          hash: "h1",
          timestamp: 1,
        })
      }
      if (url.includes("objects/mirror/node-a")) {
        return jsonResponse({ data: { pub: "a" }, hash: "h3", timestamp: 1 })
      }
      if (url.includes("objects/mirror/node-b")) {
        return jsonResponse({ data: { pub: "b" }, hash: "h4", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      cap: { iss: owner.edPub, subKem: dev.kemPub } as unknown as CapCert,
      devEdPrivHex: dev.edPriv,
      devKemPrivHex: dev.kemPriv,
      isKnownCollection: isKnown,
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({ a: { pub: "a" }, b: { pub: "b" } })
    expect(keyringPulls).toBe(0)
  })

  it("pulls the keyring exactly once when several encrypted nodes are read concurrently", async () => {
    const owner = makeParty()
    const dev = makeParty()
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPriv, edPubHex: owner.edPub },
      [{ subKemHex: dev.kemPub }],
    )
    const encryptor = await createKeyringEncryptor(
      keyring,
      { kemPubHex: dev.kemPub, kemPrivHex: dev.kemPriv },
      { trustedAdders: [owner.edPub] },
    )
    const sealedA = await encryptor.encrypt({ which: "a" })
    const sealedB = await encryptor.encrypt({ which: "b" })
    const sealedC = await encryptor.encrypt({ which: "c" })

    let keyringPulls = 0
    const fetchMock = async (url: string) => {
      if (url.includes("_keyring")) {
        keyringPulls++
        return jsonResponse({ data: keyring, hash: "h2", timestamp: 1 })
      }
      if (url.includes("objects/_index")) {
        return jsonResponse({
          data: {
            objects: [
              { id: "node-a", type: "a" },
              { id: "node-b", type: "b" },
              { id: "node-c", type: "c" },
              { id: "node-d", type: "d" },
            ],
          },
          hash: "h1",
          timestamp: 1,
        })
      }
      if (url.includes("objects/mirror/node-a")) return jsonResponse({ data: sealedA, hash: "h3", timestamp: 1 })
      if (url.includes("objects/mirror/node-b")) return jsonResponse({ data: sealedB, hash: "h4", timestamp: 1 })
      if (url.includes("objects/mirror/node-c")) return jsonResponse({ data: sealedC, hash: "h5", timestamp: 1 })
      // The mixed part: one plaintext (public-tier) node alongside three
      // encrypted ones.
      if (url.includes("objects/mirror/node-d")) return jsonResponse({ data: { plain: true }, hash: "h6", timestamp: 1 })
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      cap: { iss: owner.edPub, subKem: dev.kemPub } as unknown as CapCert,
      devEdPrivHex: dev.edPriv,
      devKemPrivHex: dev.kemPriv,
      isKnownCollection: (type) => ["a", "b", "c", "d"].includes(type),
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({
      a: { which: "a" },
      b: { which: "b" },
      c: { which: "c" },
      d: { plain: true },
    })
    expect(keyringPulls).toBe(1)
  })
})

describe("readPublicSpaceMirror", () => {
  it("reads a public node with no cap, no keyring and no object index", async () => {
    const seen: string[] = []
    const fetchMock = async (url: string) => {
      seen.push(url)
      if (url.includes("_index/objects/public")) {
        return jsonResponse({
          data: {
            [SPACE_ID]: {
              nodes: [
                { id: "node-a", type: "a", title: "A", updatedAt: 1 },
                { id: "node-x", type: "unrelated", title: "X", updatedAt: 1 },
              ],
            },
            "sp-other": { nodes: [{ id: "node-z", type: "a", title: "Z", updatedAt: 1 }] },
          },
          hash: "h1",
          timestamp: 1,
        })
      }
      if (url.includes("objects/mirror/node-a")) {
        return jsonResponse({ data: { published: true }, hash: "h2", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readPublicSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      isKnownCollection: isKnown,
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({ a: { published: true } })
    // Never touches the member-gated object index, nor the keyring, and never
    // sends an Authorization header (no cap provider on an anon client).
    expect(seen.some((u) => u.includes("objects/_index"))).toBe(false)
    expect(seen.some((u) => u.includes("_keyring"))).toBe(false)
    // The other space's node of the same type is not mixed in.
    expect(seen.some((u) => u.includes("node-z"))).toBe(false)
  })

  it("reads explicit node ids without pulling the public directory", async () => {
    const seen: string[] = []
    const fetchMock = async (url: string) => {
      seen.push(url)
      if (url.includes("objects/mirror/node-a")) {
        return jsonResponse({ data: { published: true }, hash: "h2", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readPublicSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      nodes: [{ id: "node-a", type: "a" }],
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({ a: { published: true } })
    expect(seen.some((u) => u.includes("_index/objects/public"))).toBe(false)
  })

  it("omits a node whose document unexpectedly carries _encrypted, keeping the rest", async () => {
    const fetchMock = async (url: string) => {
      if (url.includes("objects/mirror/node-a")) {
        // A public -> private flip mid-cycle: content already sealed while the
        // directory still advertises the node. Returning this blob would hand
        // the caller ciphertext it would treat as data.
        return jsonResponse({ data: { _encrypted: "deadbeef", _epoch: 0 }, hash: "h2", timestamp: 1 })
      }
      if (url.includes("objects/mirror/node-b")) {
        return jsonResponse({ data: { published: true }, hash: "h3", timestamp: 1 })
      }
      throw new Error(`unexpected fetch: ${url}`)
    }

    const result = await readPublicSpaceMirror({
      rendezvous: { baseUrl: "https://h", namespace: "ns" },
      spaceId: SPACE_ID,
      nodes: [
        { id: "node-a", type: "a" },
        { id: "node-b", type: "b" },
      ],
      docPath,
      fetch: fetchMock as unknown as typeof fetch,
    })

    expect(result).toEqual({ b: { published: true } })
    expect(result).not.toHaveProperty("a")
  })
})
