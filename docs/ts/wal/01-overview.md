# starfish-wal — WAL / CRDT documents

`@drakkar.software/starfish-wal` (TS) / `starfish-wal` (Python) implements a
write-ahead-log document model: a logical document is an **append-only log of
CRDT operations** plus a sibling `<name>__snapshot` document for fast cold-start.
Diffs are appended instead of a merged document being rewritten, so you get full
edit history, small per-edit deltas, and convergent concurrent/offline editing.

It requires **no server, wire-format, or storage-backend change** — each log
element's `data` is the existing sealed append envelope, so one transport serves
both `encryption: "none"` and `encryption: "delegated"`.

## Guides

This page is the overview. The detailed references:

1. [Overview](01-overview.md) — architecture, quick start, limitations (this page).
2. [CRDT model](02-crdt-model.md) — ops, the causal clock, LWW/RGA/text semantics,
   determinism, and the `WalCrdt` API.
3. [Document layer](03-document.md) — `WalDocument` lifecycle, the transport /
   encryptor / signer interfaces, encryption modes, and wiring to the live client.
4. [Reconcile API](04-reconcile.md) — `update` / `setText` / `setList`:
   auto-generating minimal ops from a desired value, and UI/state-store wiring.
5. [Snapshots & reader postures](05-snapshots.md) — producing trusted snapshots,
   cold-start, and the `trust` / `trust-retain-tail` / `re-derive` postures.
6. [Security model](06-security.md) — author verification, authorization, the
   per-writer sequence, encryption integration, and the threat model.

## Architecture

```
<name>            append-only collection (type: by_timestamp)
                  each element.data = sealed CRDT op-batch (one commit)
<name>__snapshot  regular (LWW) document, writeRole-gated
                  { state, uptoTs, writerSeq, producedBy, sig }
```

- **Write** — compute CRDT ops against the current materialized state, stamp each
  with a causal clock, seal the batch, author-sign it, and append. The server
  assigns the element `ts`.
- **Read** — adopt a trusted snapshot (if present), then drive an incremental
  pull from `uptoTs` and **fold** each op into the materialized state. Folding is
  commutative and idempotent, so server reordering and client retries are safe.

## The CRDT core

The fold is deterministic and **byte-identical across TypeScript and Python**,
locked by [`tests/test-vectors/wal-crdt.json`](../../../tests/test-vectors/wal-crdt.json).

| Shape | Op kinds | Semantics |
|---|---|---|
| LWW typed register | `set` / `del` | Objects / scalar fields. Highest clock `(counter, replicaId)` wins; concurrent writes to distinct fields all survive; delete is a clock-ordered tombstone. |
| RGA sequence | `ins` / `rmv` | Ordered lists. Stable element ids, insert-after, tombstone-on-delete; concurrent inserts converge by descending-clock sibling order. |
| Text | `ins` / `rmv` | An RGA whose element values are single characters; `text(list)` joins them. |

Convergence rests on these obligations:

- a **no-ties total order** `(c, replicaId)` — `replicaId` is derived from the
  author Ed25519 key plus a per-session nonce, so concurrent ops never collide;
- **idempotent ops by construction** — LWW writes keyed by `(reg, clock)`, RGA
  ops keyed by element id — so an at-least-once, out-of-order log needs no
  applied-op dedup set;
- **unique RGA element ids** — `WalDocument` derives each id as
  `<counter>@<replicaId>` from the unique clock, so ids never collide. A custom
  op producer must preserve this: two inserts that share an `id` but carry
  different content are non-commutative (first-write-wins), the standard RGA
  unique-id obligation;
- the clock lives **inside** the (encrypted) payload, so the server cannot
  observe or influence convergence ordering.

```ts
import { WalCrdt, type Op } from "@drakkar.software/starfish-wal"

const crdt = new WalCrdt()
crdt.fold([
  { t: "set", reg: "title", clock: { c: 1, r: "a" }, value: "Hello" },
  { t: "ins", list: "body", id: "1@a", after: "", clock: { c: 2, r: "a" }, value: "h" },
  { t: "ins", list: "body", id: "2@a", after: "1@a", clock: { c: 3, r: "a" }, value: "i" },
] satisfies Op[])
crdt.materialize() // { body: ["h", "i"], title: "Hello" }
crdt.text("body")  // "hi"
```

## The document layer (`WalDocument`, TypeScript)

`WalDocument` composes the CRDT with three injected concerns so it stays
testable without a live server and identical across encryption modes:

- a **`WalTransport`** (`append` / `pull` of op-batch elements) — back it with
  `StarfishClient.append` + `AppendLogCursor`;
- a **`WalEncryptor`** (`seal` / `open` one batch) — `noopEncryptor` under
  `none`, the keyring encryptor under `delegated`;
- a **`WalSigner`** — `createEd25519Signer(pub, priv)` reuses the protocol's
  `signAppendAuthor` / `signDocAuthor`.

```ts
const doc = new WalDocument({
  documentKey: "spaces/s/docs/d",
  transport,
  signer: createEd25519Signer(edPubHex, edPrivHex),
  posture: "trust-retain-tail",
})
await doc.open()
doc.setField("title", "Hello")
doc.insertText("body", 0, "draft")
await doc.commit()
await doc.pull()         // fold anything appended since (live updates)
doc.materialize()
```

### Reconcile from a desired value (auto-generated ops)

Hand-driving `insert` / `removeAt` / `insertText` is the low-level path. The
ergonomic alternative is to declare the **value you want** and let the document
compute the minimal CRDT ops by diffing it against the current state:

- **`update(next)`** — reconcile the whole document: array values are diffed as
  RGA lists, every other value is an LWW register written only when it changed,
  and keys dropped from `next` are deleted.
- **`setText(list, next)`** — character-level diff of a text list (the ergonomic
  replacement for `insertText`).
- **`setList(list, next)`** — LCS diff of an array into minimal `ins`/`rmv` ops.

```ts
await doc.open()
doc.update({ title: "Hello", tags: ["draft", "wal"] }) // initial value
await doc.commit()

doc.setText("body", "the quick brown fox")             // type some text
doc.update({ title: "Hello, world", tags: ["wal"] })   // edit title, drop a tag
await doc.commit()                                      // only the diffs are appended
```

Reconcile is convergent: kept elements retain their identity, so concurrent edits
to untouched parts merge cleanly, and re-applying the same desired value is a
no-op (nothing to commit). It is the natural way to wire a UI/state store to a WAL
document — render from `materialize()`, and feed edits back through `update()`.

### Security obligations enforced here

- **Mandatory author verification** of every op-batch and snapshot before its
  decrypted content is trusted — the JSON seal binds no AAD, so the Ed25519
  signature is the only integrity binding. Failures fail **closed**
  (`onAuthorError: "throw"`, the default).
- **Authorized-writer set** (`isAuthorizedWriter`) and **snapshot-role** gate
  (`isSnapshotAuthor`) — a signature proves authorship, not authorization.
- A **per-writer monotonic sequence** in each batch surfaces tail
  truncation/rollback (`detectedGaps()`), reconciled against the snapshot's
  `writerSeq` baseline; set `strictSequence` to fail closed on a detected gap.
  A skipped (unverified) element under `onAuthorError: "skip"` never advances the
  resume checkpoint past it, so an injected bad element cannot suppress the
  honest ops that follow.

### Snapshots and reader postures

Snapshots are **client-generated by a trusted role** (`doc.snapshot()`); the
server holds no keys and cannot fold. A reader picks a posture:

- `trust` — adopt a role-signed snapshot and replay only the tail (lowest cost);
- `trust-retain-tail` (default) — trust it but keep `retainTailN` recent,
  author-verified elements independently re-verifiable;
- `re-derive` — re-fold the signed prefix `ts ≤ uptoTs` and compare against the
  snapshot's claimed state, exposing the result as `doc.snapshotVerified`.

## Current limitations

The TypeScript package ships the CRDT core and the `WalDocument` client log; the
Python package ships the deterministic CRDT core (clock + fold) validated against
the shared vectors. Not yet implemented:

- **Python `WalDocument`** (commit / materialize / snapshot) — the Python package
  is the CRDT core only.
- **Add-wins observed-remove maps** — map-key presence currently uses the LWW
  register (a concurrent set/delete resolves by clock, not add-wins).
- **Text tombstone-GC / compaction** — tombstones from deletes are retained;
  there is no snapshot-driven compaction barrier yet.
- **Live transport wiring** — `WalTransport` / `WalEncryptor` are interfaces; the
  adapters over the live `AppendLogCursor` / `SyncManager` / keyring encryptor are
  not part of this package yet.
- **CEK seal-count rotation** and an `appendOnly && ttlMs` config guard — left to
  the server/keyring configuration for now.
