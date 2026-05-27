import { describe, it, expect, vi } from "vitest"
import { signAppendAuthor, type Encryptor } from "@drakkar.software/starfish-protocol"
import { StarfishClient } from "../src/client.js"
import { AppendLogCursor, AppendAuthorError, checkpointOf } from "../src/append-log.js"

/** A fetch stub that returns each `datas` payload on successive calls, wrapped
 *  in the standard `{ data, hash, timestamp }` pull envelope. */
function fetchReturning(...datas: unknown[]) {
  const spy = vi.fn()
  for (const data of datas) {
    spy.mockResolvedValueOnce({ ok: true, json: async () => ({ data, hash: "h", timestamp: 0 }) })
  }
  return spy
}

function makeClient(fetchSpy: ReturnType<typeof vi.fn>) {
  return new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: fetchSpy })
}

const URL_EVENTS = "https://api.example.com/v1/pull/events"

describe("AppendLogCursor — cold start", () => {
  it("first pull sends no ?checkpoint= and returns the whole collection", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events" })

    const batch = await log.pull()

    expect(fetchSpy).toHaveBeenCalledWith(URL_EVENTS, expect.any(Object))
    expect(batch).toEqual([{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }])
    expect(log.getItems()).toEqual(batch)
    expect(log.getCheckpoint()).toBe(2)
  })

  it("empty collection → empty batch, checkpoint stays 0", async () => {
    const log = new AppendLogCursor({ client: makeClient(fetchReturning({ items: [] })), pullPath: "/pull/events" })
    expect(await log.pull()).toEqual([])
    expect(log.getCheckpoint()).toBe(0)
  })

  it("keeps a ts=0 first element on cold start and doesn't re-deliver it", async () => {
    // since=0 means "no server filter", so the defensive skip must NOT drop ts=0.
    const fetchSpy = fetchReturning(
      { items: [{ ts: 0, data: { a: 1 } }, { ts: 1, data: { b: 2 } }] },
      { items: [{ ts: 0, data: { a: 1 } }, { ts: 1, data: { b: 2 } }] }, // a server echoing old items on the ?checkpoint=1 pull
    )
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events" })

    const first = await log.pull()
    expect(first).toEqual([{ ts: 0, data: { a: 1 } }, { ts: 1, data: { b: 2 } }])
    expect(log.getCheckpoint()).toBe(1)

    // Now since=1 > 0, so the defensive filter is active and the echoed items are dropped.
    expect(await log.pull()).toEqual([])
    expect(log.getItems()).toHaveLength(2)
  })
})

describe("AppendLogCursor — warm start", () => {
  it("seeded from initialItems resumes from their max ts", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 300, data: { c: 3 } }] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      initialItems: [{ ts: 100, data: { a: 1 } }, { ts: 200, data: { b: 2 } }],
    })
    expect(log.getCheckpoint()).toBe(200)

    const batch = await log.pull()

    expect(fetchSpy).toHaveBeenCalledWith(`${URL_EVENTS}?checkpoint=200`, expect.any(Object))
    expect(batch).toEqual([{ ts: 300, data: { c: 3 } }])
    expect(log.getItems()).toEqual([
      { ts: 100, data: { a: 1 } },
      { ts: 200, data: { b: 2 } },
      { ts: 300, data: { c: 3 } },
    ])
    expect(log.getCheckpoint()).toBe(300)
  })

  it("seeded from `since` only resumes without rehydrating history", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 250, data: { c: 3 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", since: 200 })

    const batch = await log.pull()

    expect(fetchSpy).toHaveBeenCalledWith(`${URL_EVENTS}?checkpoint=200`, expect.any(Object))
    expect(batch).toEqual([{ ts: 250, data: { c: 3 } }])
    expect(log.getItems()).toEqual([{ ts: 250, data: { c: 3 } }])
  })

  it("no new items → empty batch, checkpoint unchanged", async () => {
    const log = new AppendLogCursor({ client: makeClient(fetchReturning({ items: [] })), pullPath: "/pull/events", since: 200 })
    expect(await log.pull()).toEqual([])
    expect(log.getCheckpoint()).toBe(200)
    expect(log.getItems()).toEqual([])
  })

  it("defensively skips an element with ts <= checkpoint (misbehaving server)", async () => {
    // Server wrongly returns an already-held element (ts=150) alongside a new one (ts=250).
    const fetchSpy = fetchReturning({ items: [{ ts: 150, data: { a: 1 } }, { ts: 250, data: { b: 2 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", since: 200 })

    const batch = await log.pull()

    expect(batch).toEqual([{ ts: 250, data: { b: 2 } }])
    expect(log.getItems()).toEqual([{ ts: 250, data: { b: 2 } }])
    expect(log.getCheckpoint()).toBe(250)
  })
})

describe("AppendLogCursor — custom appendField", () => {
  it("reads the configured array field instead of 'items'", async () => {
    const fetchSpy = fetchReturning({ logs: [{ ts: 1, data: { x: 1 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", appendField: "logs" })
    expect(await log.pull()).toEqual([{ ts: 1, data: { x: 1 } }])
    expect(log.getCheckpoint()).toBe(1)
  })
})

describe("AppendLogCursor — checkpoint advances across pulls", () => {
  it("second pull sends the first pull's max ts as ?checkpoint=", async () => {
    const fetchSpy = fetchReturning(
      { items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] },
      { items: [{ ts: 3, data: { c: 3 } }] },
    )
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events" })

    await log.pull()
    const second = await log.pull()

    expect(fetchSpy).toHaveBeenNthCalledWith(1, URL_EVENTS, expect.any(Object))
    expect(fetchSpy).toHaveBeenNthCalledWith(2, `${URL_EVENTS}?checkpoint=2`, expect.any(Object))
    expect(second).toEqual([{ ts: 3, data: { c: 3 } }])
    expect(log.getCheckpoint()).toBe(3)
    expect(log.getItems()).toHaveLength(3)
  })

  it("setCheckpoint restores position without items", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 99, data: { z: 1 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events" })
    log.setCheckpoint(50)
    await log.pull()
    expect(fetchSpy).toHaveBeenCalledWith(`${URL_EVENTS}?checkpoint=50`, expect.any(Object))
  })

  it("setCheckpoint rejects rewinding below the max held ts", () => {
    const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: vi.fn() })
    const log = new AppendLogCursor({ client, pullPath: "/pull/events", initialItems: [{ ts: 200, data: {} }] })
    expect(() => log.setCheckpoint(100)).toThrow("checkpoint must be >= the max ts already held")
    expect(() => log.setCheckpoint(200)).not.toThrow()
  })
})

describe("AppendLogCursor — encryption", () => {
  const encryptor: Encryptor = {
    encrypt: async (d) => ({ _encrypted: JSON.stringify(d) }),
    decrypt: async (w) => JSON.parse(w._encrypted as string),
  }

  it("decrypts each element's data while preserving ts and author fields", async () => {
    const fetchSpy = fetchReturning({
      items: [
        { ts: 1, data: { _encrypted: JSON.stringify({ msg: "a" }) } },
        { ts: 2, data: { _encrypted: JSON.stringify({ msg: "b" }) }, authorPubkey: "ab" },
      ],
    })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", encryptor })

    const batch = await log.pull()

    expect(batch).toEqual([
      { ts: 1, data: { msg: "a" } },
      { ts: 2, data: { msg: "b" }, authorPubkey: "ab" },
    ])
    expect(log.getCheckpoint()).toBe(2)
  })

  it("a decryption failure is atomic — no items appended, checkpoint unchanged", async () => {
    const failing: Encryptor = {
      encrypt: async (d) => d,
      decrypt: async (w) => {
        if ((w as { bad?: boolean }).bad) throw new Error("bad key")
        return w
      },
    }
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { ok: true } }, { ts: 2, data: { bad: true } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", encryptor: failing })

    await expect(log.pull()).rejects.toThrow("bad key")
    expect(log.getItems()).toEqual([])
    expect(log.getCheckpoint()).toBe(0)
  })
})

describe("AppendLogCursor — author verification", () => {
  // A real Ed25519 keypair so the emitted signature actually verifies.
  const KP = {
    priv: "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff",
    pub: "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4",
  }

  function signedElement(ts: number, data: Record<string, unknown>) {
    const author = signAppendAuthor("events", data, KP.pub, KP.priv, "ed25519")
    return { ts, data, ...author }
  }

  it("passes when every element carries a valid signature", async () => {
    const fetchSpy = fetchReturning({ items: [signedElement(1, { msg: "a" }), signedElement(2, { msg: "b" })] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      verifyAuthor: { expectedAuthorPubkey: KP.pub, alg: "ed25519" },
    })

    const batch = await log.pull()
    expect(batch).toHaveLength(2)
    expect(log.getCheckpoint()).toBe(2)
  })

  it("throws AppendAuthorError on a tampered signature — atomic", async () => {
    const good = signedElement(1, { msg: "a" })
    const tampered = { ...signedElement(2, { msg: "b" }), data: { msg: "TAMPERED" } }
    const fetchSpy = fetchReturning({ items: [good, tampered] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", verifyAuthor: true })

    await expect(log.pull()).rejects.toBeInstanceOf(AppendAuthorError)
    expect(log.getItems()).toEqual([])
    expect(log.getCheckpoint()).toBe(0)
  })

  it("throws when an element is unsigned and verification is on", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { msg: "a" } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", verifyAuthor: true })
    await expect(log.pull()).rejects.toBeInstanceOf(AppendAuthorError)
  })

  it("throws when authorPubkey is not the expected key", async () => {
    const fetchSpy = fetchReturning({ items: [signedElement(1, { msg: "a" })] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      verifyAuthor: { expectedAuthorPubkey: "00".repeat(32), alg: "ed25519" },
    })
    await expect(log.pull()).rejects.toBeInstanceOf(AppendAuthorError)
  })

  it("rejects an element signed for a different documentKey (replay binding)", async () => {
    // A valid signature, but bound to "other" — pulling from "/pull/events" makes
    // the cursor verify over documentKey "events", so it must reject the replay.
    const data = { msg: "a" }
    const author = signAppendAuthor("other", data, KP.pub, KP.priv, "ed25519")
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data, ...author }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", verifyAuthor: true })

    await expect(log.pull()).rejects.toBeInstanceOf(AppendAuthorError)
    expect(log.getItems()).toEqual([])
  })

  it("matches expectedAuthorPubkey case-insensitively (hex)", async () => {
    const fetchSpy = fetchReturning({ items: [signedElement(1, { msg: "a" })] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      verifyAuthor: { expectedAuthorPubkey: KP.pub.toUpperCase(), alg: "ed25519" },
    })
    expect(await log.pull()).toHaveLength(1)
  })

  it("verifies over the pre-decryption ciphertext, then decrypts (verifyAuthor + encryptor)", async () => {
    const encryptor: Encryptor = {
      encrypt: async (d) => ({ _encrypted: JSON.stringify(d) }),
      decrypt: async (w) => JSON.parse(w._encrypted as string),
    }
    // The author proof is signed over the STORED bytes — the ciphertext envelope, not the plaintext.
    const ciphertext = { _encrypted: JSON.stringify({ msg: "secret" }) }
    const author = signAppendAuthor("events", ciphertext, KP.pub, KP.priv, "ed25519")
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: ciphertext, ...author }] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      encryptor,
      verifyAuthor: { expectedAuthorPubkey: KP.pub, alg: "ed25519" },
    })

    const batch = await log.pull()

    // Verification passed (no throw) AND the returned data is decrypted, ts/author preserved.
    expect(batch).toEqual([
      { ts: 1, data: { msg: "secret" }, authorPubkey: KP.pub, authorSignature: author.authorSignature },
    ])
  })
})

describe("AppendLogCursor — constructor validation", () => {
  const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", fetch: vi.fn() })

  it("throws when since < max ts of initialItems", () => {
    expect(
      () => new AppendLogCursor({ client, pullPath: "/pull/events", initialItems: [{ ts: 200, data: {} }], since: 100 }),
    ).toThrow("since must be >= the max ts of initialItems")
  })

  it("throws when since is negative", () => {
    expect(() => new AppendLogCursor({ client, pullPath: "/pull/events", since: -1 })).toThrow(
      "since must be non-negative",
    )
  })
})

describe("checkpointOf", () => {
  it("returns 0 for an empty array", () => {
    expect(checkpointOf([])).toBe(0)
  })
  it("returns the max ts", () => {
    expect(checkpointOf([{ ts: 5 }, { ts: 3 }, { ts: 9 }])).toBe(9)
  })
})

describe("AppendLogCursor — onElementError: skip", () => {
  const failing: Encryptor = {
    encrypt: async (d) => d,
    decrypt: async (w) => {
      if ((w as { bad?: boolean }).bad) throw new Error("bad key")
      return w
    },
  }
  // A real Ed25519 keypair so a valid signature actually verifies.
  const KP = {
    priv: "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff",
    pub: "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4",
  }

  it("drops an undecryptable element, keeps the rest, and advances the checkpoint past it", async () => {
    const fetchSpy = fetchReturning({
      items: [{ ts: 1, data: { ok: true } }, { ts: 2, data: { bad: true } }, { ts: 3, data: { ok: true } }],
    })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      encryptor: failing,
      onElementError: "skip",
    })

    const batch = await log.pull()
    expect(batch).toEqual([{ ts: 1, data: { ok: true } }, { ts: 3, data: { ok: true } }])
    // Checkpoint advanced PAST the skipped ts=2 so it is never re-fetched.
    expect(log.getCheckpoint()).toBe(3)
  })

  it("does not re-fetch a skipped element on the next pull", async () => {
    const fetchSpy = fetchReturning(
      { items: [{ ts: 1, data: { ok: true } }, { ts: 2, data: { bad: true } }] },
      { items: [{ ts: 3, data: { ok: true } }] },
    )
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      encryptor: failing,
      onElementError: "skip",
    })
    await log.pull()
    expect(log.getCheckpoint()).toBe(2)
    await log.pull()
    expect(fetchSpy).toHaveBeenNthCalledWith(2, `${URL_EVENTS}?checkpoint=2`, expect.any(Object))
  })

  it("skips an element that fails author verification instead of throwing", async () => {
    const good = { ts: 1, data: { msg: "a" }, ...signAppendAuthor("events", { msg: "a" }, KP.pub, KP.priv, "ed25519") }
    const tampered = { ts: 2, data: { msg: "TAMPERED" }, ...signAppendAuthor("events", { msg: "b" }, KP.pub, KP.priv, "ed25519") }
    const fetchSpy = fetchReturning({ items: [good, tampered] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      verifyAuthor: true,
      onElementError: "skip",
    })

    const batch = await log.pull()
    expect(batch).toEqual([good])
    expect(log.getCheckpoint()).toBe(2)
  })

  it("reports skippedCount to the logger", async () => {
    const pullSuccess = vi.fn()
    const logger = {
      pullStart: () => {},
      pullSuccess,
      pullError: () => {},
      pushStart: () => {},
      pushSuccess: () => {},
      pushError: () => {},
      conflict: () => {},
    }
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { ok: true } }, { ts: 2, data: { bad: true } }] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/events",
      encryptor: failing,
      onElementError: "skip",
      logger,
    })
    await log.pull()
    expect(pullSuccess).toHaveBeenCalledWith("events", expect.any(Number), { skippedCount: 1 })
  })

  it("default policy ('throw') still fails the whole pull atomically", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { ok: true } }, { ts: 2, data: { bad: true } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", encryptor: failing })
    await expect(log.pull()).rejects.toThrow("bad key")
    expect(log.getItems()).toEqual([])
    expect(log.getCheckpoint()).toBe(0)
  })
})

describe("AppendLogCursor — concurrent pull() is serialized", () => {
  it("two overlapping pulls run one-after-another and never double-append a window", async () => {
    const fetchSpy = fetchReturning(
      { items: [{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }] },
      { items: [{ ts: 3, data: { c: 3 } }] },
    )
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events" })

    const [b1, b2] = await Promise.all([log.pull(), log.pull()])

    expect(b1).toEqual([{ ts: 1, data: { a: 1 } }, { ts: 2, data: { b: 2 } }])
    expect(b2).toEqual([{ ts: 3, data: { c: 3 } }])
    expect(log.getItems()).toHaveLength(3)
    expect(log.getCheckpoint()).toBe(3)
    // The 2nd pull ran AFTER the 1st advanced the checkpoint, so it carried ?checkpoint=2.
    expect(fetchSpy).toHaveBeenNthCalledWith(2, `${URL_EVENTS}?checkpoint=2`, expect.any(Object))
  })

  it("a rejected pull does not wedge the chain for the next call", async () => {
    const spy = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockResolvedValueOnce({ ok: true, json: async () => ({ data: { items: [{ ts: 1, data: { a: 1 } }] }, hash: "h", timestamp: 0 }) })
    const log = new AppendLogCursor({ client: makeClient(spy), pullPath: "/pull/events" })

    const [r1, r2] = await Promise.allSettled([log.pull(), log.pull()])

    expect(r1.status).toBe("rejected")
    expect(r2.status).toBe("fulfilled")
    if (r2.status === "fulfilled") expect(r2.value).toEqual([{ ts: 1, data: { a: 1 } }])
  })
})

describe("AppendLogCursor — persistEncrypted (E2EE-safe persistence)", () => {
  const encryptor: Encryptor = {
    encrypt: async (d) => ({ _encrypted: JSON.stringify(d) }),
    decrypt: async (w) => JSON.parse(w._encrypted as string),
  }
  const cipher = (o: unknown) => ({ _encrypted: JSON.stringify(o) })

  it("getItems() keeps ciphertext while pull() returns decrypted and getDecryptedItems() returns the full plaintext log", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: cipher({ msg: "a" }) }, { ts: 2, data: cipher({ msg: "b" }) }] })
    const log = new AppendLogCursor({
      client: makeClient(fetchSpy),
      pullPath: "/pull/streamchat",
      encryptor,
      persistEncrypted: true,
    })

    const batch = await log.pull()
    expect(batch).toEqual([{ ts: 1, data: { msg: "a" } }, { ts: 2, data: { msg: "b" } }])
    // getItems() is the persistable CIPHERTEXT — no plaintext at rest.
    expect(log.getItems()).toEqual([{ ts: 1, data: cipher({ msg: "a" }) }, { ts: 2, data: cipher({ msg: "b" }) }])
    expect(await log.getDecryptedItems()).toEqual([{ ts: 1, data: { msg: "a" } }, { ts: 2, data: { msg: "b" } }])
  })

  it("round-trips: persisted ciphertext re-seeds and renders decrypted with no network fetch for history", async () => {
    const fetch1 = fetchReturning({ items: [{ ts: 1, data: cipher({ msg: "a" }) }, { ts: 2, data: cipher({ msg: "b" }) }] })
    const log1 = new AppendLogCursor({ client: makeClient(fetch1), pullPath: "/pull/streamchat", encryptor, persistEncrypted: true })
    await log1.pull()
    const persisted = log1.getItems() // ciphertext written to "disk"

    const fetch2 = fetchReturning({ items: [] })
    const log2 = new AppendLogCursor({
      client: makeClient(fetch2),
      pullPath: "/pull/streamchat",
      encryptor,
      persistEncrypted: true,
      initialItems: persisted,
    })
    expect(log2.getCheckpoint()).toBe(2)
    // Renders history WITHOUT touching the network.
    expect(await log2.getDecryptedItems()).toEqual([{ ts: 1, data: { msg: "a" } }, { ts: 2, data: { msg: "b" } }])
  })

  it("getDecryptedItems() honors skip for an unreadable persisted element", async () => {
    const failing: Encryptor = {
      encrypt: async (d) => d,
      decrypt: async (w) => {
        if ((w as { bad?: boolean }).bad) throw new Error("bad key")
        return JSON.parse((w as { _encrypted: string })._encrypted)
      },
    }
    const log = new AppendLogCursor({
      client: makeClient(fetchReturning({ items: [] })),
      pullPath: "/pull/streamchat",
      encryptor: failing,
      persistEncrypted: true,
      onElementError: "skip",
      initialItems: [{ ts: 1, data: cipher({ msg: "a" }) }, { ts: 2, data: { bad: true } }],
    })
    expect(await log.getDecryptedItems()).toEqual([{ ts: 1, data: { msg: "a" } }])
  })

  it("without an encryptor, persistEncrypted is a no-op (plaintext is its own stored form)", async () => {
    const fetchSpy = fetchReturning({ items: [{ ts: 1, data: { a: 1 } }] })
    const log = new AppendLogCursor({ client: makeClient(fetchSpy), pullPath: "/pull/events", persistEncrypted: true })
    await log.pull()
    expect(log.getItems()).toEqual([{ ts: 1, data: { a: 1 } }])
    expect(await log.getDecryptedItems()).toEqual([{ ts: 1, data: { a: 1 } }])
  })
})
