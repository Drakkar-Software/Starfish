/**
 * `@drakkar.software/starfish-wal` — write-ahead-log / doc-diff collections with
 * CRDT semantics and trusted snapshots.
 *
 * A logical document is an append-only op-log (`<name>`) of sealed CRDT op
 * batches, plus a sibling LWW snapshot (`<name>__snapshot`) for fast cold-start.
 * The fold is client-side, commutative, idempotent, and byte-identical across
 * TypeScript and Python (locked by `tests/test-vectors/wal-crdt.json`). No server
 * or wire-format change is required.
 */

export {
  type Clock,
  LamportClock,
  compareClocks,
  clockGreater,
  compareCodePoints,
  deriveReplicaId,
} from "./clock.js"

export {
  WalCrdt,
  type Json,
  type Op,
  type SetOp,
  type DelOp,
  type InsOp,
  type RmvOp,
  type CrdtState,
} from "./crdt.js"

export {
  WalDocument,
  createEd25519Signer,
  noopEncryptor,
  type WalDocumentOptions,
  type WalTransport,
  type WalAppendElement,
  type WalEncryptor,
  type WalSigner,
  type WalSnapshotDoc,
  type WalSnapshotStore,
  type OpBatchEnvelope,
  type ReaderPosture,
  type SequenceGap,
} from "./document.js"

// Re-exported for consumers implementing a custom WalTransport / WalSigner,
// whose signatures reference this protocol contract type.
export type { AppendAuthor } from "@drakkar.software/starfish-protocol"
