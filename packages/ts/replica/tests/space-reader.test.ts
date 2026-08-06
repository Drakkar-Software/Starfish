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
import { readSpaceMirror } from "../src/space/reader.js"

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
const docPath = (spaceId: string, nodeId: string) => `spaces/${spaceId}/objects/mirror/${nodeId}`
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

  it("throws a clear error when the space's keyring doc has no epochs yet", async () => {
    const owner = makeParty()
    const dev = makeParty()
    const fetchMock = async (url: string) => {
      if (url.includes("objects/_index")) {
        return jsonResponse({ data: { objects: [{ id: "node-a", type: "a" }] }, hash: "h1", timestamp: 1 })
      }
      if (url.includes("_keyring")) {
        return jsonResponse({ data: {}, hash: "h2", timestamp: 1 })
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
})
