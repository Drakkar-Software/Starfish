/**
 * Tests for the device-pairing rendezvous helpers.
 *
 * The identity crypto primitives and the anon client are mocked so the tests
 * exercise the orchestration: QR payload shape, the onProvisioned-before-push
 * ordering, dual-accept prefixes, the hash-guarded push, and root pinning.
 */
import { describe, it, expect, vi, beforeEach } from "vitest"

// ── Mocks (hoisted) ───────────────────────────────────────────────────────────

vi.mock("@drakkar.software/starfish-identities", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@drakkar.software/starfish-identities")>()
  return {
    ...actual,
    provisionDevice: vi.fn(async () => ({
      deviceKeys: { kemPub: "kempub-device", edPub: "edpub-device", edPriv: "edpriv-device", kemPriv: "kempriv-device" },
      bundle: { stub: "bundle" },
    })),
    sealWithPassphrase: vi.fn(async () => ({ v: 1, ct: "sealed" })),
    openWithPassphrase: vi.fn(async () =>
      new TextEncoder().encode(JSON.stringify({ keys: { edPub: "e" }, bundle: { stub: "b" } })),
    ),
    installPairingBundle: vi.fn(async (_bundle: unknown, _keys: unknown, opts: { expectedRootEdPub?: string } = {}) => {
      if (opts.expectedRootEdPub === undefined) throw new Error("root pinning required")
      return {
        credentials: {
          userId: "userid-root",
          device: { kemPub: "k", edPub: "e", edPriv: "ep", kemPriv: "kp" },
          capCert: { stub: "cap" } as never,
        },
      }
    }),
  }
})

const pushSpy = vi.fn(async () => ({ hash: "h2", timestamp: 1 }))
const pullSpy = vi.fn(async () => ({ data: { v: 1, ct: "sealed" }, hash: "h1" }))
vi.mock("../src/client.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/client.js")>()
  return {
    ...actual,
    makeAnonSpaceClient: vi.fn(() => ({ push: pushSpy, pull: pullSpy })),
  }
})

// ── Imports (after mocks) ──────────────────────────────────────────────────────

import { startDevicePairing, completeDevicePairing, DEFAULT_PAIR_PREFIX } from "../src/pairing.js"
import { defaultSpaceLayout } from "../src/layout.js"
import type { Session } from "../src/session.js"
import { provisionDevice } from "@drakkar.software/starfish-identities"

function makeSession(): Session {
  return {
    userId: "userid-root",
    keys: { edPub: "edpub-root", edPriv: "edpriv-root", kemPub: "kempub-root", kemPriv: "kempriv-root" },
    layout: defaultSpaceLayout,
    baseUrl: "https://sync.test",
    namespace: "",
  } as unknown as Session
}

const completeOpts = { baseUrl: "https://sync.test", namespace: "" }

beforeEach(() => {
  pushSpy.mockClear()
  pullSpy.mockClear()
})

describe("startDevicePairing", () => {
  it("returns a QR payload with the default prefix and root edPub after the nonce", async () => {
    const qr = await startDevicePairing(makeSession(), "1234")
    expect(qr.startsWith(DEFAULT_PAIR_PREFIX)).toBe(true)
    const body = qr.slice(qr.indexOf(":") + 1)
    const [nonce, root] = body.split(".")
    expect(nonce).toMatch(/^[0-9a-f]{32}$/)
    expect(root).toBe("edpub-root")
    expect(provisionDevice).toHaveBeenCalled()
  })

  it("uses opts.prefix when provided", async () => {
    const qr = await startDevicePairing(makeSession(), "1234", { prefix: "octospaces-pair:" })
    expect(qr.startsWith("octospaces-pair:")).toBe(true)
  })

  it("calls onProvisioned BEFORE the rendezvous push", async () => {
    const order: string[] = []
    pushSpy.mockImplementationOnce(async () => {
      order.push("push")
      return { hash: "h2", timestamp: 1 }
    })
    await startDevicePairing(makeSession(), "1234", { onProvisioned: async () => void order.push("onProvisioned") })
    expect(order).toEqual(["onProvisioned", "push"])
  })

  it("hash-guards the push with the pulled slot hash", async () => {
    await startDevicePairing(makeSession(), "1234")
    expect(pullSpy).toHaveBeenCalled()
    // third positional arg to push is the baseHash from the prior pull
    expect(pushSpy.mock.calls[0][2]).toBe("h1")
  })
})

describe("completeDevicePairing", () => {
  it("accepts a starfish-pair: payload and returns a PairResult", async () => {
    const r = await completeDevicePairing(`${DEFAULT_PAIR_PREFIX}abc123.edpub-root`, "1234", completeOpts)
    expect(r.userId).toBe("userid-root")
    expect(r.fingerprint).toBeTruthy()
    expect(r.capCert).toBeDefined()
  })

  it("accepts a legacy octochat-pair: prefix (dual-accept)", async () => {
    await expect(completeDevicePairing(`octochat-pair:abc123.edpub-root`, "1234", completeOpts)).resolves.toBeDefined()
  })

  it("pins the root from the QR payload (installPairingBundle requires it)", async () => {
    // Payload without a root segment → no pin, no confirm callback → refused.
    await expect(completeDevicePairing(`${DEFAULT_PAIR_PREFIX}abc123`, "1234", completeOpts)).rejects.toThrow()
  })

  it("throws a friendly error when the slot is empty", async () => {
    pullSpy.mockResolvedValueOnce({ data: undefined, hash: "" } as never)
    await expect(completeDevicePairing(`${DEFAULT_PAIR_PREFIX}abc.edpub-root`, "1234", completeOpts)).rejects.toThrow(
      /not found or expired/,
    )
  })
})
