/**
 * Cross-language vector tests for the v3.0 signed revocation list.
 *
 * Vector source: `tests/test-vectors/revocation-list.json`.
 *
 * Coverage:
 * - `gen1.list`: signature parses & verifies via the in-memory store's
 *   `acceptList()` accept path (which does Ed25519 verify internally).
 * - `gen2.list`: accepted, supersedes gen1.
 * - `forged.list`: rejected (`expectVerify: false`).
 * - The canonical signing input we reconstruct via `stableStringify(list \ sig)`
 *   matches `vector.canonicalSigningInput` byte-for-byte.
 */

import { describe, it, expect, beforeAll } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { webcrypto } from "node:crypto"
import {
  configurePlatform,
  stableStringify,
} from "@drakkar.software/starfish-protocol"
import {
  createInMemoryRevocationStore,
  type RevocationList,
} from "../../src/auth/revocation-store.js"

beforeAll(() => {
  configurePlatform({
    crypto: webcrypto as unknown as Crypto,
    base64: {
      encode: (data: Uint8Array) => Buffer.from(data).toString("base64"),
      decode: (str: string) => new Uint8Array(Buffer.from(str, "base64")),
    },
  })
})

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(
  __dirname,
  "../../../../../tests/test-vectors/revocation-list.json",
)

interface GenerationVector {
  list: RevocationList
  canonicalSigningInput: string
}

interface ForgedVector {
  list: RevocationList
  canonicalSigningInput: string
  expectVerify: false
}

interface RevocationVectors {
  issuer: { edPub: string; userId: string }
  subjects: {
    alice_dev_1: { edPub: string; nonce: string }
    alice_dev_2: { edPub: string; nonce: string }
  }
  generations: { "1": GenerationVector; "2": GenerationVector }
  forged: ForgedVector
}

const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as RevocationVectors

function canonicalSigningInput(list: RevocationList): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sig, ...unsigned } = list
  return stableStringify(unsigned as unknown as Record<string, unknown>)
}

describe("revocation-list vectors — canonical signing input", () => {
  it("gen1 canonical input matches vector", () => {
    const gen1 = vectors.generations["1"]
    expect(canonicalSigningInput(gen1.list)).toBe(gen1.canonicalSigningInput)
  })

  it("gen2 canonical input matches vector", () => {
    const gen2 = vectors.generations["2"]
    expect(canonicalSigningInput(gen2.list)).toBe(gen2.canonicalSigningInput)
  })

  it("forged canonical input matches gen2 (same body, tampered sig only)", () => {
    expect(canonicalSigningInput(vectors.forged.list)).toBe(
      vectors.forged.canonicalSigningInput,
    )
  })
})

describe("revocation-list vectors — signature verification via acceptList", () => {
  it("accepts gen1 list (signature verifies)", () => {
    const store = createInMemoryRevocationStore()
    const result = store.acceptList(vectors.generations["1"].list)
    expect(result.ok).toBe(true)
    const sub = vectors.subjects.alice_dev_1
    expect(store.isRevoked(vectors.issuer.edPub, sub.edPub, sub.nonce)).toBe(true)
    // alice_dev_2 is NOT yet in gen1
    const sub2 = vectors.subjects.alice_dev_2
    expect(store.isRevoked(vectors.issuer.edPub, sub2.edPub, sub2.nonce)).toBe(false)
  })

  it("accepts gen2 list and it supersedes gen1", () => {
    const store = createInMemoryRevocationStore()
    expect(store.acceptList(vectors.generations["1"].list).ok).toBe(true)
    expect(store.acceptList(vectors.generations["2"].list).ok).toBe(true)
    const sub1 = vectors.subjects.alice_dev_1
    const sub2 = vectors.subjects.alice_dev_2
    expect(store.isRevoked(vectors.issuer.edPub, sub1.edPub, sub1.nonce)).toBe(true)
    expect(store.isRevoked(vectors.issuer.edPub, sub2.edPub, sub2.nonce)).toBe(true)
  })

  it("rejects forged list (expectVerify: false)", () => {
    const store = createInMemoryRevocationStore()
    const result = store.acceptList(vectors.forged.list)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe("bad-signature")
    // No revocations were stored
    const sub1 = vectors.subjects.alice_dev_1
    expect(store.isRevoked(vectors.issuer.edPub, sub1.edPub, sub1.nonce)).toBe(false)
  })
})
