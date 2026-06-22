/**
 * Tests for `ensureKeyringRecipient` — idempotent ensure-and-add lifecycle.
 *
 * We mock `StarfishClient` at the method level so the tests run without a
 * real server. The in-memory keyring document is backed by a simple `Map`.
 */
import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { ed25519, x25519 } from "@noble/curves/ed25519.js"

import { ensureKeyringRecipient } from "../src/ensure.js"
import { createKeyring } from "../src/keyring.js"
import { ConflictError, type StarfishClient } from "@drakkar.software/starfish-client"

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

function hex(b: Uint8Array) {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

function makeId() {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPrivHex: hex(edPriv),
    edPubHex: hex(ed25519.getPublicKey(edPriv)),
    kemPrivHex: hex(kemPriv),
    kemPubHex: hex(x25519.getPublicKey(kemPriv)),
  }
}

// ── in-memory client mock ─────────────────────────────────────────────────────

/**
 * A minimal `StarfishClient` backed by an in-memory `Map`. Supports pull/push
 * and emits `StarfishHttpError`-like objects on 404. The paths are used as-is
 * (stripping the `/pull/` or `/push/` prefix to get the doc key).
 */
function makeMemClient(initial: Map<string, { data: unknown; hash: string }> = new Map()): StarfishClient & {
  docs: Map<string, { data: unknown; hash: string }>
  pushCalls: number
} {
  const docs = new Map(initial)
  let pushCalls = 0

  function docKey(path: string) {
    return path.replace(/^\/(pull|push)\//, "")
  }

  function notFound(msg: string): never {
    const err: Error & { status?: number } = new Error(msg)
    err.status = 404
    err.name = "StarfishHttpError"
    throw err
  }

  return {
    docs,
    get pushCalls() { return pushCalls },
    set pushCalls(n) { pushCalls = n },

    async pull(path: string) {
      const key = docKey(path)
      const doc = docs.get(key)
      if (!doc) notFound(`Not found: ${path}`)
      return { data: doc.data, hash: doc.hash, timestamp: 0 }
    },

    async push(path: string, data: unknown, hash: string | null) {
      const key = docKey(path)
      const current = docs.get(key)
      const currentHash = current?.hash ?? null
      if (hash !== currentHash) {
        throw new ConflictError()
      }
      pushCalls++
      const newHash = `hash-${pushCalls}`
      docs.set(key, { data, hash: newHash })
      return { hash: newHash, timestamp: Date.now() }
    },

    // Stubs for methods not used by ensure
    async append(path: string, data: unknown) { return { timestamp: Date.now() } },
    async pullBlob(path: string) { return new Uint8Array(0) },
    async pushBlob(path: string, data: Uint8Array) { return { hash: "blob-hash" } },
  } as unknown as StarfishClient & { docs: Map<string, { data: unknown; hash: string }>; pushCalls: number }
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe("ensureKeyringRecipient", () => {
  it("creates keyring and adds the recipient on first use", async () => {
    const owner = makeId()
    const member = makeId()
    const client = makeMemClient()

    const result = await ensureKeyringRecipient(
      client,
      "spaces/sp-1",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        adderKemPub: owner.kemPubHex,
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    expect(result).toBe("added")
    // The keyring doc should now exist at the conventional path.
    expect(client.docs.has("spaces/sp-1/_keyring")).toBe(true)
  })

  it("returns 'already-present' when the recipient is already in the keyring", async () => {
    const owner = makeId()
    const member = makeId()
    const client = makeMemClient()

    // First call — adds the recipient.
    await ensureKeyringRecipient(
      client,
      "spaces/sp-2",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        adderKemPub: owner.kemPubHex,
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    // Second call (idempotent) — recipient already present.
    const result = await ensureKeyringRecipient(
      client,
      "spaces/sp-2",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        adderKemPub: owner.kemPubHex,
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    expect(result).toBe("already-present")
  })

  it("succeeds when keyring already exists (does not try to re-create it)", async () => {
    const owner = makeId()
    const member = makeId()

    // Pre-create the keyring with the owner as epoch recipient.
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPrivHex, edPubHex: owner.edPubHex },
      [{ subKemHex: owner.kemPubHex }],
    )
    const initial = new Map([
      [
        "spaces/sp-3/_keyring",
        { data: keyring as unknown as Record<string, unknown>, hash: "init-hash" },
      ],
    ])
    const client = makeMemClient(initial)

    const result = await ensureKeyringRecipient(
      client,
      "spaces/sp-3",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        // adderKemPub omitted — keyring already exists; no create needed.
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    expect(result).toBe("added")
  })

  it("retries and succeeds after a hash conflict on add", async () => {
    const owner = makeId()
    const member = makeId()

    // Pre-create the keyring so the ensure function skips the create step.
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPrivHex, edPubHex: owner.edPubHex },
      [{ subKemHex: owner.kemPubHex }],
    )
    const docs = new Map([
      ["spaces/sp-4/_keyring", { data: keyring as unknown as Record<string, unknown>, hash: "h0" }],
    ])
    const client = makeMemClient(docs)

    // Intercept the FIRST push to simulate a concurrent writer bumping the hash.
    // The real push is still called on the second attempt (after retry).
    const realPush = client.push.bind(client)
    let conflictFired = false
    ;(client as unknown as { push: typeof client.push }).push = async (path, data, hash) => {
      if (path.includes("_keyring") && !conflictFired) {
        conflictFired = true
        // Bump the stored hash to simulate a concurrent write BEFORE our push.
        client.docs.set(
          "spaces/sp-4/_keyring",
          { data: keyring as unknown as Record<string, unknown>, hash: "h-concurrent" },
        )
        // Use the real ConflictError class so `instanceof` checks work.
        throw new ConflictError()
      }
      return realPush(path, data, hash)
    }

    const result = await ensureKeyringRecipient(
      client,
      "spaces/sp-4",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    expect(result).toBe("added")
  })

  it("propagates non-conflict errors immediately", async () => {
    const owner = makeId()
    const member = makeId()

    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPrivHex, edPubHex: owner.edPubHex },
      [{ subKemHex: owner.kemPubHex }],
    )
    const docs = new Map([
      ["spaces/sp-5/_keyring", { data: keyring as unknown as Record<string, unknown>, hash: "h0" }],
    ])
    const client = makeMemClient(docs)
    ;(client as unknown as { push: typeof client.push }).push = async () => {
      throw new Error("access_denied")
    }

    await expect(
      ensureKeyringRecipient(
        client,
        "spaces/sp-5",
        { subKem: member.kemPubHex },
        { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
        { recipientOpts: { trustedAdders: [owner.edPubHex] } },
      ),
    ).rejects.toThrow("access_denied")
  })

  it("respects a custom keyringPath override for the existence check and creation", async () => {
    const owner = makeId()
    const member = makeId()
    const client = makeMemClient()

    // Pre-create the keyring at the custom path so addCollectionRecipient can
    // find it through the conventional path that recipients.ts uses internally.
    // The custom keyringPath affects only the ensure check/create step.
    const { keyring } = await createKeyring(
      { edPrivHex: owner.edPrivHex, edPubHex: owner.edPubHex },
      [{ subKemHex: owner.kemPubHex }],
    )
    // Store it at both the custom path (for our create check) and the
    // conventional path (for addCollectionRecipient, which derives its own path).
    client.docs.set("custom/path/_keys", { data: keyring as unknown as Record<string, unknown>, hash: "hc" })
    client.docs.set("spaces/sp-6/_keyring", { data: keyring as unknown as Record<string, unknown>, hash: "hd" })

    const result = await ensureKeyringRecipient(
      client,
      "spaces/sp-6",
      { subKem: member.kemPubHex },
      { edPriv: owner.edPrivHex, edPub: owner.edPubHex, kemPriv: owner.kemPrivHex },
      {
        keyringPath: "custom/path/_keys",
        // adderKemPub is not needed since the keyring already exists at keyringPath.
        recipientOpts: { trustedAdders: [owner.edPubHex] },
      },
    )

    expect(result).toBe("added")
  })
})
