# WAL — Document layer (`WalDocument`)

`WalDocument` is the client document-log: it turns the [CRDT core](02-crdt-model.md)
into a working synced document by composing it with three injected concerns — a
**transport**, an **encryptor**, and a **signer**. That injection keeps it
unit-testable without a live server and **identical** under `encryption: "none"`
and `encryption: "delegated"`.

This guide covers the lifecycle, the injected interfaces, the op-batch envelope,
the low-level mutations, and how to wire it to the live `@drakkar.software/starfish-client`.
The high-level [reconcile API](04-reconcile.md), [snapshots](05-snapshots.md), and
the [security model](06-security.md) have their own guides.

## Lifecycle

```ts
import { WalDocument, createEd25519Signer } from "@drakkar.software/starfish-wal"

const doc = new WalDocument({
  documentKey: "spaces/s/docs/d",
  transport,
  signer: createEd25519Signer(edPubHex, edPrivHex),
  posture: "trust-retain-tail",
})

await doc.open()          // bootstrap: adopt a trusted snapshot (if any), fold the tail
doc.update({ title: "Hi" }) // mutate (queues ops locally)
await doc.commit()         // seal + author-sign + append ONE op-batch; returns { ts } | null
await doc.pull()           // fold everything appended since the last checkpoint (live updates)
doc.materialize()          // current value
```

- **`open()`** is required before mutating. It bootstraps per the reader
  [posture](05-snapshots.md) and resumes the per-author sequence past anything you
  already authored.
- Mutations are **queued locally** (and folded into the local view immediately, so
  `materialize()` reflects uncommitted edits and index/diff math stays correct).
- **`commit()`** flushes the queued ops as a single sealed, signed op-batch and
  returns the server-assigned `{ ts }`, or `null` if nothing was queued.
- **`pull()`** folds new elements and returns the count folded; call it on a timer,
  on a server push notification, or via cross-tab broadcast.

### Introspection

```ts
doc.materialize()        // Record<string, Json>
doc.text("body")         // a text list as a string
doc.currentCheckpoint    // resume ts of the cursor
doc.snapshotVerified     // re-derive result (see snapshots guide)
doc.detectedGaps()       // per-writer sequence gaps (see security guide)
doc.retainedTail()       // recent verified elements kept under trust-retain-tail
```

## Options

```ts
interface WalDocumentOptions {
  documentKey: string                 // op-log collection key; snapshot sibling is `${documentKey}__snapshot`
  transport: WalTransport
  signer: WalSigner
  encryptor?: WalEncryptor            // default: noopEncryptor (encryption: "none")
  snapshotStore?: WalSnapshotStore    // omit to never read/write snapshots
  sessionNonce?: string               // disambiguates concurrent sessions of one author (default "0")
  posture?: ReaderPosture             // "trust" | "trust-retain-tail" (default) | "re-derive"
  retainTailN?: number                // recent elements kept re-verifiable under trust-retain-tail (default 64)
  isAuthorizedWriter?: (authorPubHex: string) => boolean
  isSnapshotAuthor?: (authorPubHex: string) => boolean
  onAuthorError?: "throw" | "skip"    // default "throw" (fail closed)
  strictSequence?: boolean            // throw on a detected sequence gap (default false)
}
```

`sessionNonce` is important when the same author opens the document in multiple
tabs/processes concurrently: it makes the derived `replicaId` unique per session,
which the CRDT requires (see [CRDT model](02-crdt-model.md)). The security-related
options are covered in the [security guide](06-security.md).

## The op-batch envelope

Each commit produces one append element whose `data` is the sealed envelope:

```ts
interface OpBatchEnvelope {
  v: 1
  author: string // author Ed25519 pubkey (hex), bound here so it cannot be relabeled
  seq: number    // per-author monotonic sequence (truncation detection)
  ops: Op[]      // the CRDT ops for this commit
}
```

On commit the envelope is `encryptor.seal`-ed, then the **sealed** `data` is
author-signed (`signer.signAppend`), then appended via the transport. On read the
element is author-verified **before** decrypt, decrypted, and the in-payload
`author` is checked against the signed author — see [security](06-security.md).

## The injected interfaces

### `WalTransport` — append / pull

```ts
interface WalAppendElement {
  ts: number
  data: Record<string, unknown>      // the sealed envelope
  authorPubkey: string
  authorSignature: string
}

interface WalTransport {
  append(documentKey: string, body: { data: Record<string, unknown> } & AppendAuthor): Promise<{ ts: number }>
  pull(documentKey: string, checkpoint: number): Promise<WalAppendElement[]> // ts > checkpoint, ascending
}
```

The contract: `append` stores one element and the **server assigns** a strictly
increasing `ts`; `pull` returns every element with `ts > checkpoint` in ascending
`ts` order. That is exactly what an append-only (`by_timestamp`) collection plus
`AppendLogCursor` provide.

### `WalEncryptor` — seal / open

```ts
interface WalEncryptor {
  seal(plain: Record<string, unknown>): Record<string, unknown> | Promise<...>
  open(sealed: Record<string, unknown>): Record<string, unknown> | Promise<...>
}
```

- Under `encryption: "none"`, use the exported `noopEncryptor` (stores plaintext
  as-is).
- Under `encryption: "delegated"`, back it with the keyring encryptor so each
  op-batch and snapshot `state` is sealed `{ _encrypted, _epoch }`. `seal`/`open`
  may be async.

The same `WalDocument` code path serves both modes — the only difference is the
injected encryptor.

### `WalSigner` — author proof

```ts
interface WalSigner {
  authorPubHex: string
  signAppend(documentKey: string, data: Record<string, unknown>): AppendAuthor | Promise<AppendAuthor>
  signDoc(documentKey: string, data: Record<string, unknown>): AppendAuthor | Promise<AppendAuthor>
}

const signer = createEd25519Signer(edPubHex, edPrivHex)
```

`createEd25519Signer` reuses the protocol's `signAppendAuthor` (for op-batch
elements) and `signDocAuthor` (for the snapshot), so the proof is byte-identical to
what the server verifies. Provide a custom `WalSigner` to delegate to a hardware
key or a remote signer.

## Low-level mutations

The reconcile API ([guide 04](04-reconcile.md)) is the recommended way to edit, but
the primitives are available:

```ts
doc.setField("title", "Hello")     // LWW register set
doc.deleteField("title")           // LWW register tombstone
doc.insert("tags", 0, "draft")     // RGA insert at index (0 = head, ≥ len = append)
doc.push("tags", "wal")            // append to a list
doc.removeAt("tags", 1)            // remove the element at an index
doc.insertText("body", 0, "draft") // insert text char-by-char at an index
```

All of these queue ops; call `commit()` to publish them. They fold locally first,
so a multi-op batch resolves indices against the in-progress state.

## Wiring to the live client

`WalDocument` depends only on the three interfaces, so the adapters over
`@drakkar.software/starfish-client` are thin:

- **Transport** — `append` → `StarfishClient.append(path, data, { … })` (which
  auto-signs when a `capProvider` is set); `pull` → an `AppendLogCursor` over the
  same path, returning its items and advancing its checkpoint. Use a debounced
  push to coalesce a burst of commits, and adaptive polling / cross-tab broadcast
  to drive `pull()`.
- **Encryptor** — `createKeyringEncryptor(keyring, deviceKemKeys)` for
  `delegated`, or `noopEncryptor` for `none`. Discover the mode from
  `fetchServerConfig`.
- **Signer** — `createEd25519Signer(edPub, edPriv)`, or wrap your `capProvider`'s
  signing key.

> The collection must be append-only (`type: "by_timestamp"`) with
> `requireAuthorSignature` enabled, and **`ttlMs` unset** (a TTL expires the whole
> collection on read and would silently wipe a quiet WAL document). The packaged
> live adapters are a tracked follow-up; today you wire these yourself.

## Convergence across writers

Because the fold is commutative and idempotent, two writers can `commit()`
independently and converge after each `pull()`s the other's batch — no `baseHash`
compare-and-swap, no lost updates on untouched parts. Producing a *minimal,
causally-correct* op-batch still requires an up-to-date local view, so a writer
folds (via `open()` + `pull()`) before it commits.
