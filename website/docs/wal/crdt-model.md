---
sidebar_position: 2
---

# WAL — CRDT model

The heart of `starfish-wal` is a small, **op-based CRDT**: each log element carries
one or more operations, and a client folds them into a materialized document. The
fold is **commutative** (order-independent), **idempotent** (re-applying an op is a
no-op), and **byte-identical across TypeScript and Python** — locked by
[`tests/test-vectors/wal-crdt.json`](https://github.com/Drakkar-Software/Starfish/blob/master/tests/test-vectors/wal-crdt.json).

This guide documents the op encoding, the causal clock, the three CRDT shapes, the
convergence obligations, and the `WalCrdt` API. It is the layer below
[`WalDocument`](/wal/document); you can use it directly to fold a log you obtained
some other way.

## The causal clock

Every op carries a `Clock` — a Lamport counter plus a stable replica id:

```ts
interface Clock {
  c: number // Lamport counter, advanced locally before each op
  r: string // stable, unique-per-session replica id
}
```

Clocks define a **total order with no ties** (`compareClocks`): counter first,
then replica id by **Unicode code-point** order (`compareCodePoints`, matching
Python's default string comparison — *not* JavaScript's UTF‑16 order). Two
concurrent ops may share a counter, but never a replica id, so conflict resolution
is always decidable and identical in both languages.

```ts
import { compareClocks, clockGreater, LamportClock, deriveReplicaId } from "@drakkar.software/starfish-wal"

compareClocks({ c: 2, r: "a" }, { c: 2, r: "b" }) // < 0  (same counter → replica id)
clockGreater({ c: 3, r: "a" }, { c: 2, r: "z" })  // true (counter dominates)

const replicaId = deriveReplicaId(authorPubHex, sessionNonce) // "<pubhex>:<nonce>"
const clock = new LamportClock(replicaId)
clock.tick()              // { c: 1, r: replicaId }   — stamp a local op
clock.observe({ c: 9, r: "other" }) // advance past a clock seen on an incoming op
clock.tick()              // { c: 10, r: replicaId }
```

The clock lives **inside** the (encrypted) op payload, so the server never
observes or influences convergence ordering — its assigned element `ts` is used
only for incremental pulls, never for conflict resolution.

> **replica id uniqueness is load-bearing.** Derive it from the author key **plus
> a per-session nonce**: one device runs multiple tabs/sessions, so the device key
> alone is not unique. `WalDocument` does this for you via `sessionNonce`.

## Operations

An `Op` is one of four discriminated shapes:

```ts
type Op =
  | { t: "set"; reg: string;  clock: Clock; value: Json }              // LWW register write
  | { t: "del"; reg: string;  clock: Clock }                          // LWW register tombstone
  | { t: "ins"; list: string; id: string; after: string; clock: Clock; value: Json } // RGA insert
  | { t: "rmv"; list: string; id: string; clock: Clock }             // RGA remove (tombstone)
```

- `Json` is any JSON value (`null | boolean | number | string | Json[] | object`).
- `reg` / `list` are names within one document (a flat keyspace; a register and a
  list should not share a name).
- For `ins`, `after` is the id of the preceding element (`""` = list head), and
  `id` is the new element's stable id.

Op fields and the materialized output must serialize identically across languages;
the encoding mirrors the protocol's `stableStringify` (sorted keys, code-point
ordering).

## The three CRDT shapes

### LWW typed register (`set` / `del`)

Objects and scalar fields. Each named register holds a single value written
**whole**; concurrent writes converge to the highest clock, ties broken by replica
id. `del` is a clock-ordered tombstone — a later (higher-clock) `set` resurrects
the register, and a *stale* (lower-clock) `del` cannot erase a newer `set`.

```ts
crdt.fold([
  { t: "set", reg: "title", clock: { c: 1, r: "a" }, value: "draft" },
  { t: "set", reg: "title", clock: { c: 2, r: "a" }, value: "final" },
  { t: "set", reg: "title", clock: { c: 2, r: "b" }, value: "other" }, // same counter, "b" > "a"
])
crdt.getRegister("title") // "other"
```

The register value is opaque JSON written as one unit — there is **no field-level
merge inside a register**. Use a nested object value for grouped scalars, or
separate registers for fields that should merge independently.

### RGA sequence (`ins` / `rmv`)

Ordered lists with stable per-element identifiers, insert-after semantics, and
tombstone-on-delete. Concurrent inserts after the same anchor are ordered by
**descending clock** (newest first), with the element `id` breaking exact-clock
ties — so the order is total and identical across languages and fold orders.

```ts
crdt.fold([
  { t: "ins", list: "l", id: "1@a", after: "",    clock: { c: 1, r: "a" }, value: "A" },
  { t: "ins", list: "l", id: "1@b", after: "",    clock: { c: 1, r: "b" }, value: "B" }, // concurrent head
  { t: "ins", list: "l", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "C" },
])
crdt.listValues("l") // ["B", "A", "C"]
```

A removed element is **tombstoned**, not erased: it stays as an anchor so a
concurrent insert-after it still threads correctly. A `rmv` delivered **before**
its `ins` records a pending tombstone that the later insert fills in — so
out-of-order delivery still converges (regression-tested).

### Text (`ins` / `rmv`)

Text is an RGA whose element values are single characters; `text(list)` joins the
live characters into a string. There is no separate op type — text reuses
`ins`/`rmv`, so all RGA convergence guarantees apply per character.

```ts
crdt.fold([
  { t: "ins", list: "body", id: "1@a", after: "",    clock: { c: 1, r: "a" }, value: "h" },
  { t: "ins", list: "body", id: "2@a", after: "1@a", clock: { c: 2, r: "a" }, value: "i" },
])
crdt.text("body") // "hi"
```

## Convergence obligations

The fold converges **only** if these hold (`WalDocument` guarantees them; a custom
op producer must too):

- **Unique, stable replica id** — see the clock section.
- **Total order with no ties** — `(counter, replicaId)`, then element `id` for RGA
  siblings.
- **Idempotent ops by construction** — LWW writes are keyed by `(reg, clock)`, RGA
  ops by element `id`. Applying an op more than once (an at-least-once, reordered
  log, or an HTTP retry that re-appends at a new `ts`) is a structural no-op, so
  **no applied-op dedup set is needed**.
- **Unique RGA element ids** — `WalDocument` derives each id as
  `<counter>@<replicaId>` from the unique clock. Two inserts that share an `id` but
  carry different content are non-commutative (first-write-wins) — the standard RGA
  unique-id assumption; do not reuse ids.

Counters and list-element **moves** are intentionally **out of scope**: a blind
`+1` or a concurrent move is not idempotent. Model a counter as a set of unique
increments, and a move as remove + insert.

## `WalCrdt` API

```ts
import { WalCrdt, type CrdtState, type Op } from "@drakkar.software/starfish-wal"

const crdt = new WalCrdt()
crdt.apply(op)              // fold a single op
crdt.fold(ops)              // fold many (order-independent)

crdt.materialize()         // → { [name]: value | array }  (registers + lists)
crdt.getRegister("title")  // → Json | undefined (undefined if absent/deleted)
crdt.listValues("l")       // → Json[]   live element values, RGA order
crdt.listIds("l")          // → string[] live element ids,   RGA order
crdt.text("body")          // → string   live chars joined
crdt.listNames()           // → string[] all list names (live or tombstoned)

const state: CrdtState = crdt.exportState() // full state incl. tombstones + clocks
crdt.importState(state)                      // replace state (snapshot bootstrap)
crdt.clone()                                 // deep, independent copy
```

### Materialization rules

`materialize()` projects the current document as a plain object:

- every **live register** contributes its value under its name;
- every **list** contributes an array of live element values under its name;
- keys are emitted in **code-point order**, so the object stable-stringifies
  identically across languages;
- tombstones (deleted registers, removed list elements) are omitted from the
  projection but **retained in state** (and in `exportState()`), because they are
  needed for convergence and for snapshot resume.

### Snapshot state (`CrdtState`)

`exportState()` returns the full internal state — registers (with clocks and
tombstone flags) and lists (every node, including tombstones and the `pending`
flag) — which is what a [snapshot](/wal/snapshots) carries in its `state` field.
Clocks are deep-copied, so a `clone()` or exported state never aliases the live
document.

## Determinism & conformance vectors

The op encoding and the fold must produce byte-identical results in TypeScript and
Python. The shared vectors in `tests/test-vectors/wal-crdt.json` lock:

- the clock total order (including a non-BMP replica id, to catch UTF‑16-vs-code‑point bugs);
- each fold case's materialized output, asserted **order-independent** (forward,
  reversed, clock-sorted) and **idempotent** (folded twice);
- the adversarial cases: remove-before-insert with a live descendant, interior-anchor
  concurrent inserts, and a three-replica head tie-break.

Both the TS (`tests/vectors.test.ts`) and Python (`tests/test_vectors.py`) suites
iterate the same file; a divergence fails CI in both languages.

## Performance

The fold and materialize are **linear** in the op/element count; `materialize()`
uses an **iterative** DFS (an explicit stack), so a long linear chain — e.g. a
multi-thousand-character text run — does **not** recurse per element or overflow
the stack. Reproduce these locally with
`pnpm --filter @drakkar.software/starfish-wal bench` (`packages/ts/wal/tests/bench.mjs`).
Indicative single-thread Node figures:

| Operation | Scale | Time |
|---|---|---|
| Fold a linear list/text | 50,000 inserts | ~20 ms (~2.5M ops/s) |
| Merge two concurrent replicas (shuffled) | 40,000 ops | ~12 ms (~3.3M ops/s) |
| `materialize()` / `text()` | 50,000 elements | ~30 ms |
| Worst-case sibling sort (K inserts, one anchor) | 10,000 | ~2 ms |

The cost that dominates a **cold replay** is not the fold but the per-element
**Ed25519 author verification** at the [document layer](/wal/document)
(~1–2 ms/element in pure JS). That is exactly what [snapshots](/wal/snapshots)
exist to avoid — a reader adopts a snapshot and replays only the tail, so replay
cost is bounded by the tail length, not the whole history.
