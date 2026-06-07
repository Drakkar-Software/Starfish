/**
 * `WalDocument` — the client document-log over an append-only collection plus a
 * sibling snapshot document. It composes the CRDT
 * ({@link WalCrdt}) with three injected concerns so it stays unit-testable
 * without a live server and identical under `encryption: "none"` / `"delegated"`:
 *
 * - a {@link WalTransport} (append/pull of op-batch elements; the real client
 *   backs this with `StarfishClient.append` + `AppendLogCursor`),
 * - a {@link WalEncryptor} (seal/open one op-batch; a no-op under `none`, the
 *   keyring encryptor under `delegated`),
 * - a {@link WalSigner} (Ed25519 author proof over each op-batch and the
 *   snapshot, reusing the protocol's `signAppendAuthor` / `signDocAuthor`).
 *
 * Security obligations this layer discharges:
 *
 * - **Mandatory author verification** of *every* op-batch and the snapshot
 *   before trusting decrypted content (the JSON seal binds no AAD, so the
 *   Ed25519 signature is the only integrity binding; never trust decrypt-success
 *   alone). Failures fail **closed** by default (`onAuthorError: "throw"`).
 * - An optional **authorized-writer set** (`isAuthorizedWriter`) and
 *   **snapshot-role** check (`isSnapshotAuthor`) — `authorPubkey` proves a
 *   signature, not authorization.
 * - A **per-writer monotonic sequence** inside each batch so a reader can detect
 *   tail truncation/rollback, reconciled against the snapshot's
 *   `writerSeq` baseline so pruned-below-snapshot ops are not flagged.
 * - Idempotent replay safety inherited from the CRDT: a verbatim
 *   re-append at a higher `ts` folds to a no-op.
 */

import {
  signAppendAuthor,
  verifyAppendAuthor,
  signDocAuthor,
  verifyDocAuthor,
  stableStringify,
  type AppendAuthor,
} from "@drakkar.software/starfish-protocol"
import { LamportClock, compareClocks, compareCodePoints, deriveReplicaId, type Clock } from "./clock.js"
import { WalCrdt, type CrdtState, type Json, type Op } from "./crdt.js"

/** The decrypted payload carried by one append element's `data` (one commit). */
export interface OpBatchEnvelope {
  /** Envelope schema version. */
  v: 1
  /** Author Ed25519 pubkey (hex); bound here so it cannot be relabeled. */
  author: string
  /** Per-author monotonic sequence (truncation detection). */
  seq: number
  /** The CRDT ops for this commit. */
  ops: Op[]
}

/** One stored append element as returned by an incremental pull. */
export interface WalAppendElement {
  ts: number
  data: Record<string, unknown>
  authorPubkey: string
  authorSignature: string
}

/** Append/pull transport over the op-log collection. */
export interface WalTransport {
  /** Append one op-batch element; the server assigns the `ts`. */
  append(
    documentKey: string,
    body: { data: Record<string, unknown> } & AppendAuthor,
  ): Promise<{ ts: number }>
  /** Pull elements with `ts > checkpoint`, in ascending `ts` order. */
  pull(documentKey: string, checkpoint: number): Promise<WalAppendElement[]>
}

/** Seals/opens one op-batch or snapshot state. No-op under `encryption:"none"`. */
export interface WalEncryptor {
  seal(plain: Record<string, unknown>): Record<string, unknown> | Promise<Record<string, unknown>>
  open(sealed: Record<string, unknown>): Record<string, unknown> | Promise<Record<string, unknown>>
}

/** An encryptor that stores plaintext as-is (`encryption: "none"`). */
export const noopEncryptor: WalEncryptor = {
  seal: x => x,
  open: x => x,
}

/** Author-proof signer for op-batches (append) and the snapshot (doc). */
export interface WalSigner {
  authorPubHex: string
  signAppend(
    documentKey: string,
    data: Record<string, unknown>,
  ): AppendAuthor | Promise<AppendAuthor>
  signDoc(
    documentKey: string,
    data: Record<string, unknown>,
  ): AppendAuthor | Promise<AppendAuthor>
}

/** Build an Ed25519 {@link WalSigner} from a keypair (hex), reusing the
 *  protocol's author-proof construction (byte-identical to the server's check). */
export function createEd25519Signer(authorPubHex: string, authorPrivHex: string): WalSigner {
  return {
    authorPubHex,
    signAppend: (k, d) => signAppendAuthor(k, d, authorPubHex, authorPrivHex),
    signDoc: (k, d) => signDocAuthor(k, d, authorPubHex, authorPrivHex),
  }
}

/** The trusted snapshot document (sibling LWW collection `<name>__snapshot`). */
export interface WalSnapshotDoc {
  /** Sealed materialized {@link CrdtState}. */
  state: Record<string, unknown>
  /** The contiguous `ts`-prefix this snapshot folded (also the resume point). */
  uptoTs: number
  /** Per-author highest sequence covered (truncation/compaction reasoning). */
  writerSeq: Record<string, number>
  /** Producing (snapshot-role) identity, Ed25519 pubkey hex. */
  producedBy: string
  authorPubkey: string
  authorSignature: string
}

/** Read/write the sibling snapshot document. */
export interface WalSnapshotStore {
  read(snapshotKey: string): Promise<WalSnapshotDoc | null>
  write(snapshotKey: string, doc: WalSnapshotDoc): Promise<void>
}

/** Reader verification posture. */
export type ReaderPosture = "trust" | "trust-retain-tail" | "re-derive"

export interface WalDocumentOptions {
  /** Op-log collection key (the snapshot sibling is `<documentKey>__snapshot`). */
  documentKey: string
  transport: WalTransport
  signer: WalSigner
  /** Defaults to {@link noopEncryptor} (`encryption: "none"`). */
  encryptor?: WalEncryptor
  snapshotStore?: WalSnapshotStore
  /** Disambiguates concurrent sessions of one author for the replica id. */
  sessionNonce?: string
  /** Defaults to `"trust-retain-tail"`. */
  posture?: ReaderPosture
  /** Recent diffs kept re-verifiable under `trust-retain-tail` (default 64). */
  retainTailN?: number
  /** Authorized-writer gate; rejected authors fail per {@link onAuthorError}. */
  isAuthorizedWriter?: (authorPubHex: string) => boolean
  /** Snapshot-role gate; an unauthorized snapshot is ignored (cold start). */
  isSnapshotAuthor?: (authorPubHex: string) => boolean
  /** What to do when author verification / authorization fails (default throw). */
  onAuthorError?: "throw" | "skip"
  /** When `true`, a detected per-writer sequence gap (a missing `seq`, i.e. a
   *  possible mid-stream truncation/rollback) throws — failing closed
   *  independent of {@link onAuthorError} — instead of only being recorded in
   *  {@link WalDocument.detectedGaps}. Note: this catches *gaps* in a writer's
   *  seen sequence; it cannot, by itself, detect truncation of a writer's
   *  newest tail (nothing bounds the tail above the last snapshot's
   *  `writerSeq`). Default `false`. */
  strictSequence?: boolean
}

/** A detected per-writer sequence gap (possible tail truncation / rollback). */
export interface SequenceGap {
  author: string
  expected: number
  got: number
}

const SNAPSHOT_SUFFIX = "__snapshot"

/**
 * One logical WAL document: `open()` → mutate → `commit()`; `pull()` for live
 * updates; `snapshot()` for a trusted-role client to checkpoint the log.
 */
export class WalDocument {
  private readonly documentKey: string
  private readonly snapshotKey: string
  private readonly transport: WalTransport
  private readonly signer: WalSigner
  private readonly encryptor: WalEncryptor
  private readonly snapshotStore?: WalSnapshotStore
  private readonly posture: ReaderPosture
  private readonly retainTailN: number
  private readonly isAuthorizedWriter?: (a: string) => boolean
  private readonly isSnapshotAuthor?: (a: string) => boolean
  private readonly onAuthorError: "throw" | "skip"
  private readonly strictSequence: boolean
  private readonly replicaId: string

  private crdt = new WalCrdt()
  private clock: LamportClock
  private checkpoint = 0
  private opened = false
  private localSeq = 0
  private pending: Op[] = []

  /** Highest contiguous per-author sequence folded so far (incl. snapshot baseline). */
  private writerSeq = new Map<string, number>()
  private gaps: SequenceGap[] = []
  private retained: WalAppendElement[] = []

  /** `re-derive`: whether the role-signed snapshot matched the re-folded prefix.
   *  `undefined` until `open()`; `null` when no authorized snapshot was present. */
  snapshotVerified: boolean | null = null

  constructor(opts: WalDocumentOptions) {
    this.documentKey = opts.documentKey
    this.snapshotKey = opts.documentKey + SNAPSHOT_SUFFIX
    this.transport = opts.transport
    this.signer = opts.signer
    this.encryptor = opts.encryptor ?? noopEncryptor
    this.snapshotStore = opts.snapshotStore
    this.posture = opts.posture ?? "trust-retain-tail"
    this.retainTailN = opts.retainTailN ?? 64
    this.isAuthorizedWriter = opts.isAuthorizedWriter
    this.isSnapshotAuthor = opts.isSnapshotAuthor
    this.onAuthorError = opts.onAuthorError ?? "throw"
    this.strictSequence = opts.strictSequence ?? false
    this.replicaId = deriveReplicaId(opts.signer.authorPubHex, opts.sessionNonce ?? "0")
    this.clock = new LamportClock(this.replicaId)
  }

  /** Bootstrap: adopt a trusted snapshot if present, then fold the tail. */
  async open(): Promise<void> {
    if (this.opened) return
    if (this.posture === "re-derive") {
      await this.bootstrapReDerive()
    } else {
      await this.bootstrapTrust()
    }
    this.opened = true
    // Resume our local sequence past anything we already authored.
    this.localSeq = this.writerSeq.get(this.signer.authorPubHex) ?? 0
  }

  private assertOpen(): void {
    if (!this.opened) throw new Error("WalDocument: call open() before mutating")
  }

  // ── Bootstrap ────────────────────────────────────────────────────────────────

  private async bootstrapTrust(): Promise<void> {
    const snap = await this.loadTrustedSnapshot()
    if (snap) {
      const state = (await this.encryptor.open(snap.doc.state)) as unknown as CrdtState
      this.crdt.importState(state)
      this.checkpoint = snap.doc.uptoTs
      for (const [a, s] of Object.entries(snap.doc.writerSeq)) this.writerSeq.set(a, s)
      this.snapshotVerified = null
    }
    await this.pull()
  }

  private async bootstrapReDerive(): Promise<void> {
    // Replay the whole signed log from ts=0; if an authorized snapshot exists,
    // re-fold its claimed prefix and compare — a mismatch flags a bad snapshot.
    const snap = await this.loadTrustedSnapshot()
    const all = await this.transport.pull(this.documentKey, 0)
    if (snap) {
      const prefix = new WalCrdt()
      for (const el of all) {
        if (el.ts > snap.doc.uptoTs) continue
        const env = await this.verifyAndOpen(el)
        if (env) prefix.fold(env.ops)
      }
      // Compare FULL canonical state, not the materialized projection: the
      // projection drops tombstones, register clocks, and element ids, so a
      // validly-signed-but-poisoned snapshot that materializes identically (e.g.
      // an inflated register clock that later suppresses a legitimate write)
      // would otherwise pass. Full-state equality covers everything that
      // influences future folds.
      const claimedState = (await this.encryptor.open(snap.doc.state)) as unknown as CrdtState
      this.snapshotVerified = canonicalState(prefix.exportState()) === canonicalState(claimedState)
    }
    let advance = true
    for (const el of all) {
      const ok = await this.ingest(el)
      if (!ok) advance = false
      if (advance && ok && el.ts > this.checkpoint) this.checkpoint = el.ts
    }
  }

  private async loadTrustedSnapshot(): Promise<{ doc: WalSnapshotDoc } | null> {
    if (!this.snapshotStore) return null
    const doc = await this.snapshotStore.read(this.snapshotKey)
    if (!doc) return null
    const content = snapshotContent(doc)
    if (!verifyDocAuthor(this.snapshotKey, content, doc.authorPubkey, doc.authorSignature)) {
      // A present-but-forged snapshot: record `false` (distinct from `null` =
      // "no snapshot") so a rejected forgery is observable even under "skip".
      this.snapshotVerified = false
      return this.fail("snapshot author signature invalid") ?? null
    }
    if (doc.producedBy !== doc.authorPubkey) {
      this.snapshotVerified = false
      return this.fail("snapshot producedBy/author mismatch") ?? null
    }
    if (this.isSnapshotAuthor && !this.isSnapshotAuthor(doc.authorPubkey)) {
      // Untrusted snapshot role: ignore it and start cold (not an error).
      return null
    }
    return { doc }
  }

  // ── Incremental pull (live updates) ────────────────────────────────────────────

  /** Pull, verify, and fold everything appended since the last checkpoint.
   *  Returns the number of elements folded. */
  async pull(): Promise<number> {
    const els = await this.transport.pull(this.documentKey, this.checkpoint)
    let folded = 0
    let advance = true
    for (const el of els) {
      const ok = await this.ingest(el)
      if (ok) folded += 1
      else advance = false
      // Advance the checkpoint only across a CONTIGUOUS prefix of verified
      // elements. A skipped (failed-verification) element under
      // onAuthorError:"skip" must not move the checkpoint past it — otherwise a
      // malicious server could inject one bad element to permanently suppress
      // the honest ops that follow. Later good elements are still folded (and
      // re-fetched/re-folded idempotently next pull) but do not advance it.
      if (advance && ok && el.ts > this.checkpoint) this.checkpoint = el.ts
    }
    return folded
  }

  private async ingest(el: WalAppendElement): Promise<boolean> {
    const env = await this.verifyAndOpen(el)
    if (!env) return false
    this.trackSequence(env)
    for (const op of env.ops) this.clock.observe(opClock(op))
    this.crdt.fold(env.ops)
    if (this.posture === "trust-retain-tail") {
      this.retained.push(el)
      if (this.retained.length > this.retainTailN) this.retained.shift()
    }
    return true
  }

  /** Author-verify, authorize, decrypt, and validate one element's envelope.
   *  Returns the envelope, or `null` if it was skipped under `onAuthorError`. */
  private async verifyAndOpen(el: WalAppendElement): Promise<OpBatchEnvelope | null> {
    if (!verifyAppendAuthor(this.documentKey, el.data, el.authorPubkey, el.authorSignature)) {
      return this.fail(`author signature invalid (ts=${el.ts})`)
    }
    if (this.isAuthorizedWriter && !this.isAuthorizedWriter(el.authorPubkey)) {
      return this.fail(`unauthorized writer ${el.authorPubkey} (ts=${el.ts})`)
    }
    const env = (await this.encryptor.open(el.data)) as unknown as OpBatchEnvelope
    if (!env || env.v !== 1 || !Array.isArray(env.ops)) {
      return this.fail(`malformed op-batch (ts=${el.ts})`)
    }
    // Bind the in-payload author to the signed element author (the seal binds no AAD).
    if (env.author !== el.authorPubkey) {
      return this.fail(`envelope author/element author mismatch (ts=${el.ts})`)
    }
    return env
  }

  private trackSequence(env: OpBatchEnvelope): void {
    const cur = this.writerSeq.get(env.author) ?? 0
    if (env.seq <= cur) return // replay / already covered (idempotent)
    if (env.seq > cur + 1) {
      this.gaps.push({ author: env.author, expected: cur + 1, got: env.seq })
      // strictSequence fails closed on a gap independent of onAuthorError (which
      // governs author-verification failures, a separate concern).
      if (this.strictSequence) {
        throw new Error(
          `WalDocument: sequence gap for ${env.author}: expected ${cur + 1}, got ${env.seq}`,
        )
      }
    }
    this.writerSeq.set(env.author, env.seq)
  }

  private fail(msg: string): null {
    if (this.onAuthorError === "throw") throw new Error(`WalDocument: ${msg}`)
    return null
  }

  // ── Mutations (build ops, fold locally, queue for commit) ───────────────────────

  /** LWW-set a named register to `value`. */
  setField(name: string, value: Json): void {
    this.enqueue({ t: "set", reg: name, clock: this.clock.tick(), value })
  }

  /** LWW-delete (tombstone) a named register. */
  deleteField(name: string): void {
    this.enqueue({ t: "del", reg: name, clock: this.clock.tick() })
  }

  /** Insert `value` into a list at `index` (0 = head, ≥ length = append). */
  insert(list: string, index: number, value: Json): void {
    this.assertOpen()
    const ids = this.crdt.listIds(list)
    const after = index <= 0 ? "" : (ids[Math.min(index, ids.length) - 1] ?? "")
    const clock = this.clock.tick()
    this.enqueue({ t: "ins", list, id: elementId(clock), after, clock, value })
  }

  /** Append `value` to the end of a list. */
  push(list: string, value: Json): void {
    this.assertOpen()
    this.insert(list, this.crdt.listIds(list).length, value)
  }

  /** Remove the element at `index` from a list. */
  removeAt(list: string, index: number): void {
    this.assertOpen()
    const id = this.crdt.listIds(list)[index]
    if (id === undefined) return
    this.enqueue({ t: "rmv", list, id, clock: this.clock.tick() })
  }

  /** Insert text (one RGA element per character) at `index` of a text list. */
  insertText(list: string, index: number, text: string): void {
    this.assertOpen()
    let at = index
    for (const ch of text) {
      this.insert(list, at, ch)
      at += 1
    }
  }

  // ── High-level reconcile (auto-generate ops from a desired value) ───────────────

  /**
   * Reconcile a list to a desired array of values, emitting the **minimal** RGA
   * `ins`/`rmv` ops to get there (an LCS diff of the current vs. next values).
   * You hand it the value you want; it computes the CRDT operations — no manual
   * index math. Kept elements retain their identity (and concurrent edits to
   * them converge); only genuinely added/removed values produce ops. Values are
   * compared structurally.
   */
  setList(list: string, next: readonly Json[]): void {
    this.assertOpen()
    const ids = this.crdt.listIds(list)
    const cur = this.crdt.listValues(list)
    const { keptCur, keptNextToCur } = lcsMatch(cur, next)

    // Remove every current element absent from the desired sequence.
    for (let i = 0; i < ids.length; i++) {
      if (!keptCur.has(i)) this.enqueue({ t: "rmv", list, id: ids[i]!, clock: this.clock.tick() })
    }
    // Insert every desired value absent from current, anchored after the element
    // that precedes it in the final order (a kept id, or the last inserted id).
    let afterId = ""
    for (let j = 0; j < next.length; j++) {
      const matchedCur = keptNextToCur.get(j)
      if (matchedCur !== undefined) {
        afterId = ids[matchedCur]!
      } else {
        const clock = this.clock.tick()
        const id = elementId(clock)
        this.enqueue({ t: "ins", list, id, after: afterId, clock, value: next[j]! })
        afterId = id
      }
    }
  }

  /**
   * Reconcile a text list to a desired string, emitting the minimal per-character
   * `ins`/`rmv` ops (a character-level diff). The ergonomic alternative to
   * hand-driving {@link insertText}: pass the whole new string and the diff is
   * computed for you. Concurrent character edits still converge.
   */
  setText(list: string, next: string): void {
    this.setList(list, [...next])
  }

  /**
   * Reconcile the whole document to a desired plain object, auto-generating ops:
   * array values are diffed as RGA lists ({@link setList}); every other value is
   * an LWW register written only when it changed; keys dropped from `next` are
   * deleted (or cleared, for a list). The high-level entry point — give it the
   * next document, it produces the CRDT ops. (A key is treated consistently as
   * either a register or a list; don't switch a key between the two.)
   */
  update(next: Record<string, Json>): void {
    this.assertOpen()
    const current = this.crdt.materialize()
    for (const [key, value] of Object.entries(next)) {
      if (Array.isArray(value)) {
        this.setList(key, value)
      } else if (!(key in current) || !deepEqualJson(current[key], value)) {
        this.setField(key, value)
      }
    }
    for (const key of Object.keys(current)) {
      if (key in next) continue
      if (Array.isArray(current[key])) this.setList(key, [])
      else this.deleteField(key)
    }
  }

  private enqueue(op: Op): void {
    this.assertOpen()
    this.crdt.apply(op)
    this.pending.push(op)
  }

  // ── Commit ────────────────────────────────────────────────────────────────────

  /** Seal, author-sign, and append the queued ops as one op-batch. Returns the
   *  server-assigned `ts`, or `null` if there was nothing to commit. */
  async commit(): Promise<{ ts: number } | null> {
    this.assertOpen()
    if (this.pending.length === 0) return null
    const seq = this.localSeq + 1
    const envelope: OpBatchEnvelope = {
      v: 1,
      author: this.signer.authorPubHex,
      seq,
      ops: this.pending,
    }
    const data = await this.encryptor.seal(envelope as unknown as Record<string, unknown>)
    const proof = await this.signer.signAppend(this.documentKey, data)
    const res = await this.transport.append(this.documentKey, { data, ...proof })
    this.localSeq = seq
    this.pending = []
    return res
  }

  // ── Snapshot (trusted-role producer) ────────────────────────────────────────────

  /**
   * Materialize the full log and write a trusted snapshot.
   * The caller must hold the snapshot `writeRole` (enforced by the server on the
   * sibling collection) and full-history key custody under `delegated`.
   */
  async snapshot(): Promise<WalSnapshotDoc> {
    if (!this.snapshotStore) throw new Error("WalDocument: no snapshotStore configured")
    const all = await this.transport.pull(this.documentKey, 0)
    const folded = new WalCrdt()
    const writerSeq: Record<string, number> = {}
    let uptoTs = 0
    for (const el of all) {
      const env = await this.verifyAndOpen(el)
      if (!env) continue
      folded.fold(env.ops)
      if (el.ts > uptoTs) uptoTs = el.ts
      if ((writerSeq[env.author] ?? 0) < env.seq) writerSeq[env.author] = env.seq
    }
    const sealedState = await this.encryptor.seal(
      folded.exportState() as unknown as Record<string, unknown>,
    )
    const partial = {
      state: sealedState,
      uptoTs,
      writerSeq,
      producedBy: this.signer.authorPubHex,
    }
    const proof = await this.signer.signDoc(this.snapshotKey, snapshotContent(partial))
    const doc: WalSnapshotDoc = { ...partial, ...proof }
    await this.snapshotStore.write(this.snapshotKey, doc)
    return doc
  }

  // ── Projections / introspection ─────────────────────────────────────────────────

  /** The current materialized document. */
  materialize(): Record<string, Json> {
    return this.crdt.materialize()
  }

  /** A named list materialized as text (1-char element values). */
  text(list: string): string {
    return this.crdt.text(list)
  }

  /** Detected per-writer sequence gaps (possible truncation/rollback). */
  detectedGaps(): readonly SequenceGap[] {
    return this.gaps
  }

  /** Retained recent elements kept re-verifiable under `trust-retain-tail`. */
  retainedTail(): readonly WalAppendElement[] {
    return this.retained
  }

  /** The cursor's current resume checkpoint (`ts`). */
  get currentCheckpoint(): number {
    return this.checkpoint
  }
}

/** The canonical signed content of a snapshot (excludes the proof fields). */
function snapshotContent(
  doc: Pick<WalSnapshotDoc, "state" | "uptoTs" | "writerSeq" | "producedBy">,
): Record<string, unknown> {
  return {
    state: doc.state,
    uptoTs: doc.uptoTs,
    writerSeq: doc.writerSeq,
    producedBy: doc.producedBy,
  }
}

/** Stable element id for an RGA insert: `<counter>@<replicaId>` (unique). */
function elementId(clock: Clock): string {
  return `${clock.c}@${clock.r}`
}

function opClock(op: Op): Clock {
  return op.clock
}

/** Structural equality for JSON values (used by the reconcile diff). */
function deepEqualJson(a: Json | undefined, b: Json | undefined): boolean {
  return stableStringify(a as unknown) === stableStringify(b as unknown)
}

/**
 * Match two value sequences for the reconcile diff: returns the set of kept `cur`
 * indices and a map from each kept `next` index to its matched `cur` index — the
 * basis for turning a desired array into minimal RGA `ins`/`rmv` ops.
 *
 * The common prefix and suffix are trimmed first (kept 1:1), and the quadratic
 * LCS runs only on the differing middle window. A localized edit (the common
 * case — a few characters changed in a long text) is therefore ~linear in the
 * document length; only a wholesale change degrades to O(m·n) on the middle.
 */
function lcsMatch(
  cur: readonly Json[],
  next: readonly Json[],
): { keptCur: Set<number>; keptNextToCur: Map<number, number> } {
  const m = cur.length
  const n = next.length
  const keptCur = new Set<number>()
  const keptNextToCur = new Map<number, number>()

  // Common prefix.
  let p = 0
  while (p < m && p < n && deepEqualJson(cur[p], next[p])) {
    keptCur.add(p)
    keptNextToCur.set(p, p)
    p++
  }
  // Common suffix (not overlapping the prefix).
  let s = 0
  while (s < m - p && s < n - p && deepEqualJson(cur[m - 1 - s], next[n - 1 - s])) {
    keptCur.add(m - 1 - s)
    keptNextToCur.set(n - 1 - s, m - 1 - s)
    s++
  }
  // LCS over only the differing middle: cur[p, m-s) vs next[p, n-s).
  const aLen = m - s - p
  const bLen = n - s - p
  if (aLen > 0 && bLen > 0) {
    const dp: number[][] = Array.from({ length: aLen + 1 }, () => new Array<number>(bLen + 1).fill(0))
    for (let i = aLen - 1; i >= 0; i--) {
      for (let j = bLen - 1; j >= 0; j--) {
        dp[i]![j] = deepEqualJson(cur[p + i], next[p + j])
          ? dp[i + 1]![j + 1]! + 1
          : Math.max(dp[i + 1]![j]!, dp[i]![j + 1]!)
      }
    }
    let i = 0
    let j = 0
    while (i < aLen && j < bLen) {
      if (deepEqualJson(cur[p + i], next[p + j])) {
        keptCur.add(p + i)
        keptNextToCur.set(p + j, p + i)
        i++
        j++
      } else if (dp[i + 1]![j]! >= dp[i]![j + 1]!) {
        i++
      } else {
        j++
      }
    }
  }
  return { keptCur, keptNextToCur }
}

/**
 * A canonical, comparable string for a full {@link CrdtState}. `stableStringify`
 * sorts object keys but NOT array order, and `exportState`'s per-list node arrays
 * are in Map-insertion order (fold-order dependent), so each list's nodes are
 * first sorted by `(clock, id)` to make two equal states compare equal
 * regardless of how they were folded. Used by the `re-derive` posture to detect
 * a snapshot whose full state (incl. tombstones and clocks) diverges from the log.
 */
function canonicalState(state: CrdtState): string {
  const lists: Record<string, unknown> = {}
  for (const key of Object.keys(state.lists)) {
    const nodes = [...state.lists[key]!]
      .map(n => ({
        // Normalize to a fixed field set so a state serialized without `pending`
        // (e.g. an externally-authored snapshot) does not falsely mismatch.
        id: n.id,
        after: n.after,
        clock: n.clock,
        value: n.value,
        deleted: n.deleted,
        pending: n.pending ?? false,
      }))
      .sort((a, b) => compareClocks(a.clock, b.clock) || compareCodePoints(a.id, b.id))
    lists[key] = nodes
  }
  return stableStringify({ regs: state.regs, lists })
}
