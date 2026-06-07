/**
 * The deterministic, op-based CRDT at the heart of `starfish-wal`. It folds a
 * log of operations into a materialized document such that:
 *
 * - **Commutative** — applying the same set of ops in any order yields the same
 *   state (so the server's reorderable element `ts` is safe to ignore for
 *   convergence).
 * - **Idempotent** — applying an op more than once is a structural no-op (so an
 *   HTTP retry that re-appends the same op under a new `ts` cannot corrupt
 *   state, and **no applied-op dedup set is needed**).
 * - **Cross-language deterministic** — TypeScript and Python fold byte-identical
 *   results, locked by `tests/test-vectors/wal-crdt.json`.
 *
 * Two CRDT shapes are provided, addressed by name within one document:
 *
 * - **LWW typed register** (`set`/`del`) — objects / scalar fields. The register
 *   value is opaque JSON written whole; concurrent writes converge to the
 *   highest `(clock)`, ties broken by `replicaId`.
 * - **RGA sequence** (`ins`/`rmv`) — ordered lists, and **text** as a sequence
 *   of single-character values. Stable per-element ids, insert-after, and
 *   tombstone-on-delete give convergent concurrent insert/delete.
 */

import { type Clock, clockGreater, compareClocks, compareCodePoints } from "./clock.js"

/** Any JSON value (the register payload / list element value). */
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json }

/** LWW register write: set named register `reg` to `value`. */
export interface SetOp {
  t: "set"
  reg: string
  clock: Clock
  value: Json
}

/** LWW register delete (tombstone) of named register `reg`. */
export interface DelOp {
  t: "del"
  reg: string
  clock: Clock
}

/** RGA insert of element `id` after `after` ("" = list head) in list `list`. */
export interface InsOp {
  t: "ins"
  list: string
  id: string
  after: string
  clock: Clock
  value: Json
}

/** RGA remove (tombstone) of element `id` in list `list`. */
export interface RmvOp {
  t: "rmv"
  list: string
  id: string
  clock: Clock
}

/** A single CRDT operation. */
export type Op = SetOp | DelOp | InsOp | RmvOp

interface RegState {
  clock: Clock
  value: Json
  deleted: boolean
}

interface RgaNode {
  id: string
  after: string
  clock: Clock
  value: Json
  deleted: boolean
  /** True for a tombstone created by a `rmv` whose `ins` has not yet arrived:
   *  its `after`/`clock`/`value` are placeholders the insert will fill in. */
  pending: boolean
}

/** A serializable snapshot of full CRDT state (registers + lists, tombstones
 *  included) — what a snapshot document carries in its `state` field. */
export interface CrdtState {
  v: 1
  regs: Record<string, RegState>
  lists: Record<string, RgaNode[]>
}

/**
 * The CRDT document: a bag of named LWW registers and named RGA sequences.
 * `apply`/`fold` ingest ops idempotently; `materialize` projects the current
 * value; `exportState`/`importState` move full state in and out of snapshots.
 */
export class WalCrdt {
  private regs = new Map<string, RegState>()
  private lists = new Map<string, Map<string, RgaNode>>()

  /** Apply one op. Commutative and idempotent: re-applying a seen op (or
   *  applying ops out of order) converges to the same state. */
  apply(op: Op): void {
    switch (op.t) {
      case "set":
        this.applyReg(op.reg, op.clock, op.value, false)
        break
      case "del":
        this.applyReg(op.reg, op.clock, null, true)
        break
      case "ins":
        this.applyIns(op)
        break
      case "rmv":
        this.applyRmv(op)
        break
    }
  }

  /** Fold a batch of ops (order-independent). */
  fold(ops: Iterable<Op>): void {
    for (const op of ops) this.apply(op)
  }

  private applyReg(reg: string, clock: Clock, value: Json, deleted: boolean): void {
    const cur = this.regs.get(reg)
    // LWW: keep the write with the highest clock. Equal clock ⇒ identical op
    // (unique replica ids) ⇒ idempotent no-op.
    if (cur && !clockGreater(clock, cur.clock)) return
    this.regs.set(reg, { clock, value, deleted })
  }

  private ensureList(list: string): Map<string, RgaNode> {
    let nodes = this.lists.get(list)
    if (!nodes) {
      nodes = new Map()
      this.lists.set(list, nodes)
    }
    return nodes
  }

  private applyIns(op: InsOp): void {
    const nodes = this.ensureList(op.list)
    const existing = nodes.get(op.id)
    if (existing) {
      // If a `rmv` arrived first it left a *pending* tombstone placeholder with
      // no real position; the insert now supplies the true `after`/`clock`/
      // `value` (the element stays deleted). This is what keeps the fold
      // commutative under out-of-order delivery — the placeholder must not own
      // the insert's anchor. A non-pending hit is a verbatim replay → no-op.
      if (existing.pending) {
        existing.after = op.after
        existing.clock = op.clock
        existing.value = op.value
        existing.pending = false
      }
      return
    }
    nodes.set(op.id, {
      id: op.id,
      after: op.after,
      clock: op.clock,
      value: op.value,
      deleted: false,
      pending: false,
    })
  }

  private applyRmv(op: RmvOp): void {
    const nodes = this.ensureList(op.list)
    const node = nodes.get(op.id)
    if (!node) {
      // Remove arriving before its insert: a *pending* tombstone placeholder.
      // The later insert fills in the real position (see applyIns); until then
      // its `after: ""` is provisional and never owns the insert's anchor.
      nodes.set(op.id, {
        id: op.id,
        after: "",
        clock: op.clock,
        value: null,
        deleted: true,
        pending: true,
      })
      return
    }
    node.deleted = true
  }

  /** Ordered live element ids of a list (RGA order, tombstones skipped). */
  private listOrder(nodes: Map<string, RgaNode>): RgaNode[] {
    // RGA: children grouped by their `after` anchor; siblings sharing an anchor
    // are ordered by DESCENDING clock (newest-first), so a later insert-after
    // the same anchor lands immediately after it. Deterministic across
    // languages via compareClocks. Pre-order DFS from the head ("").
    const children = new Map<string, RgaNode[]>()
    for (const node of nodes.values()) {
      const bucket = children.get(node.after)
      if (bucket) bucket.push(node)
      else children.set(node.after, [node])
    }
    for (const bucket of children.values()) {
      // Descending clock; break exact-clock ties on the unique element id so the
      // order is total (and stable-sort-independent) even for malformed ops
      // whose id and clock are decoupled.
      bucket.sort((a, b) => compareClocks(b.clock, a.clock) || compareCodePoints(b.id, a.id))
    }
    // Iterative pre-order DFS (an explicit stack, NOT recursion): a long linear
    // chain — e.g. a multi-thousand-character text run — would otherwise overflow
    // the call stack. Push each bucket reversed so siblings pop in bucket order.
    const out: RgaNode[] = []
    const head = children.get("")
    const stack: RgaNode[] = head ? [...head].reverse() : []
    while (stack.length > 0) {
      const node = stack.pop()!
      out.push(node)
      const kids = children.get(node.id)
      if (kids) for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]!)
    }
    return out
  }

  /** Names of all RGA lists currently present (live or tombstoned). */
  listNames(): string[] {
    return [...this.lists.keys()].sort(compareCodePoints)
  }

  /** Live element values of a named list, in RGA order. */
  listValues(list: string): Json[] {
    const nodes = this.lists.get(list)
    if (!nodes) return []
    return this.listOrder(nodes)
      .filter(n => !n.deleted)
      .map(n => n.value)
  }

  /** Live element ids of a named list, in RGA order (for index→id resolution). */
  listIds(list: string): string[] {
    const nodes = this.lists.get(list)
    if (!nodes) return []
    return this.listOrder(nodes)
      .filter(n => !n.deleted)
      .map(n => n.id)
  }

  /** A named list materialized as a string (text CRDT: 1-char element values). */
  text(list: string): string {
    return this.listValues(list)
      .map(v => (typeof v === "string" ? v : ""))
      .join("")
  }

  /** Current value of a named register, or `undefined` if absent/deleted. */
  getRegister(reg: string): Json | undefined {
    const cur = this.regs.get(reg)
    if (!cur || cur.deleted) return undefined
    return cur.value
  }

  /**
   * Project the current document: every live register by name, plus every list
   * as an array of live element values. Keys are emitted in code-point order so
   * the materialized object stable-stringifies identically across languages.
   */
  materialize(): Record<string, Json> {
    const out: Record<string, Json> = {}
    const keys = new Set<string>()
    for (const [reg, st] of this.regs) if (!st.deleted) keys.add(reg)
    for (const list of this.lists.keys()) keys.add(list)
    for (const key of [...keys].sort(compareCodePoints)) {
      const reg = this.regs.get(key)
      if (reg && !reg.deleted) {
        out[key] = reg.value
      } else {
        out[key] = this.listValues(key)
      }
    }
    return out
  }

  /** Export full CRDT state (tombstones included) for a snapshot. Clocks are
   *  deep-copied so an exported state (and {@link clone}) never aliases the
   *  live document's nested clock objects. */
  exportState(): CrdtState {
    const regs: Record<string, RegState> = {}
    for (const [reg, st] of this.regs) regs[reg] = { ...st, clock: { ...st.clock } }
    const lists: Record<string, RgaNode[]> = {}
    for (const [list, nodes] of this.lists) {
      lists[list] = [...nodes.values()].map(n => ({ ...n, clock: { ...n.clock } }))
    }
    return { v: 1, regs, lists }
  }

  /** Replace state from a snapshot's `state` (used by bootstrap readers). */
  importState(state: CrdtState): void {
    this.regs = new Map()
    this.lists = new Map()
    for (const [reg, st] of Object.entries(state.regs)) {
      this.regs.set(reg, { ...st, clock: { ...st.clock } })
    }
    for (const [list, nodes] of Object.entries(state.lists)) {
      const m = new Map<string, RgaNode>()
      // Default `pending` for forward/cross-language compatibility with a state
      // serialized without it (Python defaults it the same way on import).
      for (const n of nodes) m.set(n.id, { ...n, clock: { ...n.clock }, pending: n.pending ?? false })
      this.lists.set(list, m)
    }
  }

  /** A deep, independent copy (e.g. to fold a tail without mutating a base). */
  clone(): WalCrdt {
    const c = new WalCrdt()
    c.importState(this.exportState())
    return c
  }
}
