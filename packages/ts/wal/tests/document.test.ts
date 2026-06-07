import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { ed25519 } from "@noble/curves/ed25519.js"
import {
  WalDocument,
  createEd25519Signer,
  noopEncryptor,
  type WalAppendElement,
  type WalEncryptor,
  type WalSnapshotDoc,
  type WalSnapshotStore,
  type WalTransport,
  type OpBatchEnvelope,
  type Op,
} from "../src/index.js"

beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    configurePlatform({
      base64: {
        encode: data => Buffer.from(data).toString("base64"),
        decode: str => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
})

const DOC = "spaces/s/docs/d"

function bytesToHex(b: Uint8Array): string {
  return [...b].map(x => x.toString(16).padStart(2, "0")).join("")
}

function keypair(): { pubHex: string; privHex: string } {
  const priv = ed25519.utils.randomSecretKey()
  return { privHex: bytesToHex(priv), pubHex: bytesToHex(ed25519.getPublicKey(priv)) }
}

function signer(): ReturnType<typeof createEd25519Signer> {
  const kp = keypair()
  return createEd25519Signer(kp.pubHex, kp.privHex)
}

/** In-memory append-only collection that assigns strictly increasing `ts`. */
class FakeTransport implements WalTransport {
  readonly els: WalAppendElement[] = []
  private seq = 0
  async append(_key: string, body: { data: Record<string, unknown> } & { authorPubkey: string; authorSignature: string }) {
    this.seq += 1
    this.els.push({ ts: this.seq, ...body })
    return { ts: this.seq }
  }
  async pull(_key: string, checkpoint: number) {
    return this.els.filter(e => e.ts > checkpoint)
  }
}

class FakeSnapshotStore implements WalSnapshotStore {
  private docs = new Map<string, WalSnapshotDoc>()
  async read(key: string) {
    return this.docs.get(key) ?? null
  }
  async write(key: string, doc: WalSnapshotDoc) {
    this.docs.set(key, doc)
  }
  poke(key: string, mutate: (d: WalSnapshotDoc) => void) {
    const d = this.docs.get(key)!
    mutate(d)
  }
}

/** A "delegated"-style encryptor: opaque wrapper the signature is computed over. */
const wrappingEncryptor: WalEncryptor = {
  seal: obj => ({ _encrypted: JSON.stringify(obj), _epoch: 1 }),
  open: sealed => JSON.parse((sealed as { _encrypted: string })._encrypted),
}

describe("WalDocument commit/materialize", () => {
  it("round-trips a commit through a fresh reader (encryption: none)", async () => {
    const transport = new FakeTransport()
    const writer = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await writer.open()
    writer.setField("title", "hello")
    writer.push("tags", "a")
    writer.push("tags", "b")
    await writer.commit()

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ tags: ["a", "b"], title: "hello" })
  })

  it("works identically through a sealing encryptor (encryption: delegated)", async () => {
    const transport = new FakeTransport()
    const writer = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      encryptor: wrappingEncryptor,
    })
    await writer.open()
    writer.setField("n", 42)
    await writer.commit()
    // The stored element is opaque ciphertext, not plaintext ops.
    expect(transport.els[0]!.data).toHaveProperty("_encrypted")

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      encryptor: wrappingEncryptor,
    })
    await reader.open()
    expect(reader.materialize()).toEqual({ n: 42 })
  })

  it("converges two concurrent writers regardless of pull order", async () => {
    const transport = new FakeTransport()
    const a = new WalDocument({ documentKey: DOC, transport, signer: signer(), sessionNonce: "A" })
    const b = new WalDocument({ documentKey: DOC, transport, signer: signer(), sessionNonce: "B" })
    await a.open()
    await b.open()
    a.setField("x", 1)
    a.push("list", "a-item")
    await a.commit()
    b.setField("y", 2)
    b.push("list", "b-item")
    await b.commit()
    await a.pull()
    await b.pull()
    expect(a.materialize()).toEqual(b.materialize())
    expect(a.materialize()).toMatchObject({ x: 1, y: 2 })
  })
})

describe("WalDocument author verification", () => {
  it("rejects an element with a tampered author signature (fail closed)", async () => {
    const transport = new FakeTransport()
    const writer = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await writer.open()
    writer.setField("k", "v")
    await writer.commit()
    transport.els[0]!.authorSignature = "AAAA" // tamper

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await expect(reader.open()).rejects.toThrow(/author signature invalid/)
  })

  it("skips bad elements under onAuthorError:'skip'", async () => {
    const transport = new FakeTransport()
    const writer = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await writer.open()
    writer.setField("k", "v")
    await writer.commit()
    transport.els[0]!.authorSignature = "AAAA"

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      onAuthorError: "skip",
    })
    await reader.open()
    expect(reader.materialize()).toEqual({})
  })

  it("rejects writers outside the authorized set", async () => {
    const transport = new FakeTransport()
    const writer = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await writer.open()
    writer.setField("k", "v")
    await writer.commit()

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      isAuthorizedWriter: () => false,
    })
    await expect(reader.open()).rejects.toThrow(/unauthorized writer/)
  })
})

describe("WalDocument per-writer sequence", () => {
  it("detects a sequence gap (possible tail truncation)", async () => {
    const transport = new FakeTransport()
    const s = signer()
    const enc = noopEncryptor
    const rawAppend = async (seq: number) => {
      const env: OpBatchEnvelope = {
        v: 1,
        author: s.authorPubHex,
        seq,
        ops: [{ t: "set", reg: "k", clock: { c: seq, r: "raw" }, value: seq }],
      }
      const data = await enc.seal(env as unknown as Record<string, unknown>)
      const proof = await s.signAppend(DOC, data)
      await transport.append(DOC, { data, ...proof })
    }
    await rawAppend(1)
    await rawAppend(3) // seq 2 missing

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.detectedGaps()).toEqual([{ author: s.authorPubHex, expected: 2, got: 3 }])
  })
})

describe("WalDocument snapshots", () => {
  async function seedLog(transport: FakeTransport, store: FakeSnapshotStore, snapSigner = signer()) {
    const writer = new WalDocument({
      documentKey: DOC,
      transport,
      signer: snapSigner,
      snapshotStore: store,
    })
    await writer.open()
    writer.setField("title", "doc")
    writer.push("body", "one")
    await writer.commit()
    writer.push("body", "two")
    await writer.commit()
    return writer
  }

  it("produces a snapshot a fresh reader adopts without replaying from 0", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const writer = await seedLog(transport, store)
    const snap = await writer.snapshot()
    expect(snap.uptoTs).toBe(2)

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "trust",
    })
    await reader.open()
    expect(reader.materialize()).toEqual({ body: ["one", "two"], title: "doc" })
    // Resumed at the snapshot cutoff rather than from ts=0.
    expect(reader.currentCheckpoint).toBe(2)
  })

  it("re-derive confirms a faithful snapshot against the log", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const writer = await seedLog(transport, store)
    await writer.snapshot()

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "re-derive",
    })
    await reader.open()
    expect(reader.snapshotVerified).toBe(true)
    expect(reader.materialize()).toEqual({ body: ["one", "two"], title: "doc" })
  })

  it("re-derive flags a role-signed snapshot that disagrees with the log", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const s = signer()
    await seedLog(transport, store, s)

    // A malicious-but-authorized producer signs a state that lies about the log.
    const snapshotKey = DOC + "__snapshot"
    const content = {
      state: { v: 1, regs: { title: { clock: { c: 1, r: "x" }, value: "WRONG", deleted: false } }, lists: {} },
      uptoTs: 2,
      writerSeq: {},
      producedBy: s.authorPubHex,
    }
    const proof = await s.signDoc(snapshotKey, content)
    await store.write(snapshotKey, { ...content, ...proof } as unknown as WalSnapshotDoc)

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "re-derive",
    })
    await reader.open()
    expect(reader.snapshotVerified).toBe(false)
    // The signed op-log is intact, so the re-derived value is still correct.
    expect(reader.materialize()).toEqual({ body: ["one", "two"], title: "doc" })
  })

  it("ignores a snapshot from an unauthorized role (cold start)", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const writer = await seedLog(transport, store)
    await writer.snapshot()

    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "trust",
      isSnapshotAuthor: () => false,
    })
    await reader.open()
    // Fell back to a full replay from ts=0 — still correct.
    expect(reader.materialize()).toEqual({ body: ["one", "two"], title: "doc" })
    expect(reader.currentCheckpoint).toBe(2)
  })

  it("retains a verifiable tail under trust-retain-tail", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    await seedLog(transport, store)
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "trust-retain-tail",
      retainTailN: 1,
    })
    await reader.open()
    expect(reader.retainedTail()).toHaveLength(1)
    expect(reader.retainedTail()[0]!.ts).toBe(2)
  })

  it("trims the retained tail to the last N across incremental pulls", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.setField("a", 1)
    await w.commit() // ts1
    w.setField("b", 2)
    await w.commit() // ts2
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      posture: "trust-retain-tail",
      retainTailN: 2,
    })
    await reader.open()
    expect(reader.retainedTail().map(e => e.ts)).toEqual([1, 2])
    w.setField("c", 3)
    await w.commit() // ts3
    await reader.pull()
    expect(reader.retainedTail().map(e => e.ts)).toEqual([2, 3])
  })
})

describe("WalDocument lifecycle & idempotence", () => {
  it("resolves list indices within a single multi-op commit", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.push("l", "a")
    w.push("l", "b")
    w.insert("l", 1, "MID")
    await w.commit()
    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ l: ["a", "MID", "b"] })
  })

  it("deleteField and removeAt take effect through a fresh reader", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.setField("a", 1)
    w.setField("b", 2)
    w.deleteField("a")
    w.push("l", "x")
    w.push("l", "y")
    w.removeAt("l", 0)
    w.removeAt("l", 99) // out of range → no-op
    await w.commit()
    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ b: 2, l: ["y"] })
  })

  it("resumes the per-author sequence across sessions (no false gap)", async () => {
    const transport = new FakeTransport()
    const s = signer()
    const d1 = new WalDocument({ documentKey: DOC, transport, signer: s })
    await d1.open()
    d1.setField("a", 1)
    await d1.commit() // seq 1
    d1.setField("b", 2)
    await d1.commit() // seq 2
    // A new session for the SAME author must continue at seq 3, not restart at 1.
    const d2 = new WalDocument({ documentKey: DOC, transport, signer: s })
    await d2.open()
    d2.setField("c", 3)
    await d2.commit()
    const last = transport.els[transport.els.length - 1]!
    expect((last.data as { seq: number }).seq).toBe(3)
    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.detectedGaps()).toEqual([])
  })

  it("is idempotent when a committed element is re-appended at a higher ts (retry)", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.push("l", "a")
    await w.commit() // ts1
    // Simulate a server that committed then the client retried: same element, new ts.
    transport.els.push({ ...transport.els[0]!, ts: 99 })
    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ l: ["a"] }) // not ["a","a"]
  })

  it("round-trips through an async (Promise) encryptor incl. snapshot re-derive", async () => {
    const asyncEnc: WalEncryptor = {
      seal: async o => ({ _e: JSON.stringify(o) }),
      open: async s => JSON.parse((s as { _e: string })._e),
    }
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const s = signer()
    const w = new WalDocument({
      documentKey: DOC,
      transport,
      signer: s,
      encryptor: asyncEnc,
      snapshotStore: store,
    })
    await w.open()
    w.setField("k", 7)
    await w.commit()
    await w.snapshot()
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      encryptor: asyncEnc,
      snapshotStore: store,
      posture: "re-derive",
    })
    await reader.open()
    expect(reader.snapshotVerified).toBe(true)
    expect(reader.materialize()).toEqual({ k: 7 })
  })
})

describe("WalDocument security regressions", () => {
  it("skip mode folds good ops after a bad element without advancing past it", async () => {
    const transport = new FakeTransport()
    const s = signer()
    await appendBatch(transport, s, 1, [{ t: "set", reg: "a", clock: { c: 1, r: s.authorPubHex }, value: 1 }]) // ts1
    await transport.append(DOC, { data: { junk: 1 }, authorPubkey: s.authorPubHex, authorSignature: "AAAA" }) // ts2 bad
    await appendBatch(transport, s, 2, [{ t: "set", reg: "b", clock: { c: 2, r: s.authorPubHex }, value: 2 }]) // ts3
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      onAuthorError: "skip",
    })
    await reader.open()
    // The good op after the skipped bad element is NOT suppressed…
    expect(reader.materialize()).toEqual({ a: 1, b: 2 })
    // …and the checkpoint did not advance past the unverified element.
    expect(reader.currentCheckpoint).toBe(1)
  })

  it("re-derive flags a snapshot that diverges only in tombstones (materialize-equal)", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const s = signer()
    const snapKey = DOC + "__snapshot"
    const w = new WalDocument({ documentKey: DOC, transport, signer: s, snapshotStore: store })
    await w.open()
    w.setField("title", "doc")
    await w.commit()
    await w.snapshot()
    // Poison the snapshot with a deleted (tombstone) register that materialize()
    // hides, then RE-SIGN so the signature stays valid — the old materialize()
    // comparison would have passed; the full-state comparison must catch it.
    store.poke(snapKey, d => {
      ;(d.state as { regs: Record<string, unknown> }).regs.ghost = {
        clock: { c: 1, r: "z" },
        value: null,
        deleted: true,
      }
    })
    const poisoned = (await store.read(snapKey))!
    const proof = await s.signDoc(snapKey, {
      state: poisoned.state,
      uptoTs: poisoned.uptoTs,
      writerSeq: poisoned.writerSeq,
      producedBy: poisoned.producedBy,
    })
    store.poke(snapKey, d => {
      d.authorPubkey = proof.authorPubkey
      d.authorSignature = proof.authorSignature
    })
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "re-derive",
    })
    await reader.open()
    expect(reader.snapshotVerified).toBe(false)
    expect(reader.materialize()).toEqual({ title: "doc" })
  })

  it("strictSequence fails closed on a detected gap", async () => {
    const transport = new FakeTransport()
    const s = signer()
    await appendBatch(transport, s, 1, [{ t: "set", reg: "a", clock: { c: 1, r: s.authorPubHex }, value: 1 }])
    await appendBatch(transport, s, 3, [{ t: "set", reg: "b", clock: { c: 3, r: s.authorPubHex }, value: 2 }]) // seq 2 missing
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      strictSequence: true,
    })
    await expect(reader.open()).rejects.toThrow(/sequence gap/)
  })

  it("strictSequence fails closed even under onAuthorError:'skip'", async () => {
    const transport = new FakeTransport()
    const s = signer()
    await appendBatch(transport, s, 1, [{ t: "set", reg: "a", clock: { c: 1, r: s.authorPubHex }, value: 1 }])
    await appendBatch(transport, s, 3, [{ t: "set", reg: "b", clock: { c: 3, r: s.authorPubHex }, value: 2 }])
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      strictSequence: true,
      onAuthorError: "skip", // governs author-verification, NOT sequence strictness
    })
    await expect(reader.open()).rejects.toThrow(/sequence gap/)
  })

  it("does not flag a gap for ops pruned below a snapshot baseline, but still flags a genuine post-snapshot gap", async () => {
    const transport = new FakeTransport()
    const store = new FakeSnapshotStore()
    const s = signer()
    const w = new WalDocument({ documentKey: DOC, transport, signer: s, snapshotStore: store })
    await w.open()
    w.setField("a", 1)
    await w.commit() // ts1 seq1
    w.setField("b", 2)
    await w.commit() // ts2 seq2
    await w.snapshot() // covers writerSeq[s]=2, uptoTs=2
    transport.els.splice(0, 2) // compaction: prune ts1, ts2
    await appendBatch(transport, s, 3, [{ t: "set", reg: "c", clock: { c: 3, r: s.authorPubHex }, value: 3 }]) // ts3 seq3
    const reader = new WalDocument({
      documentKey: DOC,
      transport,
      signer: signer(),
      snapshotStore: store,
      posture: "trust",
    })
    await reader.open()
    // seq3 follows the snapshot baseline of 2 — no gap despite seq1/seq2 pruned.
    expect(reader.detectedGaps()).toEqual([])
    expect(reader.materialize()).toEqual({ a: 1, b: 2, c: 3 })
    // A genuine post-snapshot gap is still detected.
    await appendBatch(transport, s, 5, [{ t: "set", reg: "d", clock: { c: 5, r: s.authorPubHex }, value: 4 }]) // seq5, 4 missing
    await reader.pull()
    expect(reader.detectedGaps()).toEqual([{ author: s.authorPubHex, expected: 4, got: 5 }])
  })

  it("re-derive with no snapshot leaves snapshotVerified null", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.setField("a", 1)
    await w.commit()
    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer(), posture: "re-derive" })
    await reader.open()
    expect(reader.snapshotVerified).toBeNull()
    expect(reader.materialize()).toEqual({ a: 1 })
  })
})

describe("WalDocument reconcile (auto-diff API)", () => {
  /** ops folded into the most recent committed batch (noop-encryptor only). */
  const lastOps = (t: FakeTransport): Op[] =>
    (t.els[t.els.length - 1]!.data as { ops: Op[] }).ops

  it("setText computes a minimal character diff and reads back", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.setText("body", "hello")
    await w.commit()
    // Unchanged → no ops at all.
    w.setText("body", "hello")
    expect(await w.commit()).toBeNull()
    // One-character substitution "hello" → "hallo": remove 'e', insert 'a' = 2 ops.
    w.setText("body", "hallo")
    await w.commit()
    expect(lastOps(transport)).toHaveLength(2)

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.text("body")).toBe("hallo")
  })

  it("edits a large text with minimal ops via prefix/suffix trim", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    const base = "x".repeat(5000)
    w.setText("body", base)
    await w.commit()
    // Insert one character in the middle: exactly one `ins` op despite 5k chars.
    w.setText("body", base.slice(0, 2500) + "Z" + base.slice(2500))
    await w.commit()
    expect(lastOps(transport)).toHaveLength(1)

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.text("body")).toBe(base.slice(0, 2500) + "Z" + base.slice(2500))
  })

  it("setList reconciles an array with minimal ops, keeping unchanged elements", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.setList("items", ["a", "b", "c"])
    await w.commit()
    w.setList("items", ["a", "x", "c"]) // replace middle
    await w.commit()
    expect(lastOps(transport)).toHaveLength(2) // rmv b, ins x

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ items: ["a", "x", "c"] })
  })

  it("update auto-generates ops for registers + lists and deletes removed keys", async () => {
    const transport = new FakeTransport()
    const w = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await w.open()
    w.update({ title: "v1", tags: ["a", "b"] })
    await w.commit()
    w.update({ title: "v2", tags: ["a", "b", "c"] }) // title changed, tag appended
    await w.commit()
    // Re-applying the same desired document yields no ops.
    w.update({ title: "v2", tags: ["a", "b", "c"] })
    expect(await w.commit()).toBeNull()
    // Dropping `title` deletes the register; the list survives.
    w.update({ tags: ["a", "b", "c"] })
    await w.commit()

    const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
    await reader.open()
    expect(reader.materialize()).toEqual({ tags: ["a", "b", "c"] })
  })

  it("converges concurrent reconcile edits from two writers", async () => {
    const transport = new FakeTransport()
    const a = new WalDocument({ documentKey: DOC, transport, signer: signer(), sessionNonce: "A" })
    const b = new WalDocument({ documentKey: DOC, transport, signer: signer(), sessionNonce: "B" })
    await a.open()
    await b.open()
    a.update({ title: "from-a" })
    a.setText("body", "hello")
    await a.commit()
    b.setText("note", "hi")
    await b.commit()
    await a.pull()
    await b.pull()
    expect(a.materialize()).toEqual(b.materialize())
    expect(a.text("body")).toBe("hello")
    expect(a.materialize()).toMatchObject({ title: "from-a" })
  })
})

/** Append a signed op-batch with an explicit per-author sequence (test helper). */
async function appendBatch(
  transport: FakeTransport,
  s: ReturnType<typeof createEd25519Signer>,
  seq: number,
  ops: Op[],
  enc: WalEncryptor = noopEncryptor,
): Promise<void> {
  const env: OpBatchEnvelope = { v: 1, author: s.authorPubHex, seq, ops }
  const data = await enc.seal(env as unknown as Record<string, unknown>)
  const proof = await s.signAppend(DOC, data)
  await transport.append(DOC, { data, ...proof })
}
