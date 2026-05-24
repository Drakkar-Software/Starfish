/**
 * Pairing-rendezvous helpers — behavioral tests.
 *
 * Exercises the phone → computer return leg over a fake in-memory client:
 *  - rendezvousPathFor derives a deterministic, path-safe slot from the qrNonce
 *  - push → fetch → install round-trip (the bundle the root pushes is fetched
 *    and installed by the new device)
 *  - one-shot: clearPairingBundle empties the slot, a later fetch returns null
 *  - an empty/never-written slot fetches as null
 */

import { describe, it, expect, beforeAll } from "vitest"
import { webcrypto } from "node:crypto"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import type { StarfishClient } from "@drakkar.software/starfish-client"
import { deriveRootIdentity } from "../src/identity.js"
import { scopes } from "../src/cap-mint.js"
import {
  buildPairingQr,
  parsePairingQr,
  assemblePairingBundle,
  installPairingBundle,
  generateDeviceKeys,
} from "../src/pairing.js"
import {
  rendezvousPathFor,
  pushPairingBundle,
  fetchPairingBundle,
  clearPairingBundle,
  RENDEZVOUS_PREFIX,
} from "../src/rendezvous.js"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: (data) => Buffer.from(data).toString("base64"),
        decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
  if (!globalThis.crypto) {
    // @ts-expect-error — Node test shim
    globalThis.crypto = webcrypto
  }
})

/**
 * Minimal in-memory stand-in for StarfishClient. The rendezvous helpers only
 * call `.pull` / `.push`; a missing slot pulls as `{ data: {}, hash: "" }` (this
 * server's behavior), and pushes are last-write-wins (no conflict in a single-
 * threaded test, so the baseHash is accepted as-is).
 */
function makeFakeClient() {
  const store = new Map<string, { data: Record<string, unknown>; hash: string }>()
  let counter = 0
  const client = {
    store,
    async pull(path: string) {
      const key = path.replace(/^\/pull\//, "")
      return store.get(key) ?? { data: {}, hash: "" }
    },
    async push(path: string, data: Record<string, unknown>, _baseHash: string | null) {
      const key = path.replace(/^\/push\//, "")
      const hash = `h${++counter}`
      store.set(key, { data, hash })
      return { hash }
    },
  }
  return client as unknown as StarfishClient & { store: typeof store }
}

function deviceCredsFrom(keys: ReturnType<typeof generateDeviceKeys>) {
  return { edPriv: keys.edPriv, edPub: keys.edPub, kemPriv: keys.kemPriv, kemPub: keys.kemPub }
}

describe("rendezvousPathFor", () => {
  it("derives a deterministic, path-safe slot from the (base64) qrNonce", () => {
    const nonceB64 = Buffer.from(new Uint8Array(16).fill(0xab)).toString("base64")
    const path = rendezvousPathFor(nonceB64)
    expect(path).toBe(`${RENDEZVOUS_PREFIX}/${"ab".repeat(16)}`)
    // Stable across calls; the derived slot id is pure hex (no base64 specials).
    expect(rendezvousPathFor(nonceB64)).toBe(path)
    const slotId = path.slice(RENDEZVOUS_PREFIX.length + 1)
    expect(slotId).toMatch(/^[0-9a-f]+$/)
  })
})

describe("pushPairingBundle / fetchPairingBundle / clearPairingBundle", () => {
  it("round-trips: root pushes, new device fetches + installs, then one-shots the slot", async () => {
    const root = await deriveRootIdentity("alice-root-passphrase")
    const device = generateDeviceKeys()
    const qr = buildPairingQr(device.edPub, device.kemPub, scopes.rootAll())
    const parsed = parsePairingQr(qr)
    const bundle = await assemblePairingBundle(
      { edPriv: root.keys.edPriv, edPub: root.keys.edPub },
      parsed,
      {},
      { grantedScope: parsed.requestedScope },
    )

    const client = makeFakeClient()
    // New device side: nothing there yet.
    expect(await fetchPairingBundle(client, parsed.qrNonce)).toBeNull()

    // Root side: publish the bundle.
    await pushPairingBundle(client, parsed.qrNonce, bundle)

    // New device side: a single fetch retrieves the bundle and installs it,
    // pinning both the session nonce and the (known) root identity.
    const fetched = await fetchPairingBundle(client, parsed.qrNonce)
    expect(fetched).not.toBeNull()
    const installed = await installPairingBundle(fetched!, deviceCredsFrom(device), {
      now: bundle.capCert.nbf + 5,
      expectedQrNonce: parsed.qrNonce,
      expectedRootEdPub: root.keys.edPub,
    })
    expect(installed.credentials.device.edPub).toBe(device.edPub)
    expect(installed.credentials.rootEdPub).toBe(root.keys.edPub)

    // One-shot: clearing empties the slot; a later fetch returns null.
    await clearPairingBundle(client, parsed.qrNonce)
    expect(await fetchPairingBundle(client, parsed.qrNonce)).toBeNull()
  })

  it("returns null for an empty / never-written slot", async () => {
    const client = makeFakeClient()
    const nonceB64 = Buffer.from(new Uint8Array(16).fill(0x01)).toString("base64")
    expect(await fetchPairingBundle(client, nonceB64)).toBeNull()
  })
})
