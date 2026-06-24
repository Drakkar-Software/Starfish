---
sidebar_position: 6
---

# WAL — Security model

This guide is the security reference for the WAL document layer. The one-line trust
boundary:

> The server is trusted for **availability and ordering only** — never for
> confidentiality, authorship, or completeness. An authorized writer is trusted not
> to *impersonate*, but **not** restricted in *what paths it writes*. The snapshot
> role is trusted for *materialization integrity* under `trust` /
> `trust-retain-tail`, but **not** under `re-derive`.

## Mandatory author verification

Every stored element carries an Ed25519 author proof over `{ documentKey, data }`
(the **sealed** envelope), reusing the protocol's `signAppendAuthor`. On read,
`WalDocument` verifies **before** it trusts any decrypted content, in this order:

1. **signature** valid for the element's self-declared `authorPubkey`;
2. **authorization** — `isAuthorizedWriter(authorPubkey)` (if provided);
3. **decrypt** the envelope;
4. **author binding** — the in-payload `author` must equal the signed
   `authorPubkey`.

This ordering matters because the JSON seal **binds no AAD**: the GCM tag alone
does not stop a hostile server relocating a ciphertext to another path or
re-labelling its `_epoch`. The Ed25519 signature (which covers `documentKey` +
the sealed `data`) is the *only* integrity binding, so WAL **never trusts
decrypt-success alone** and author-verifies every op-batch and snapshot.

### Fail closed

`onAuthorError` defaults to `"throw"`: a bad signature, an unauthorized writer, a
malformed envelope, or an author/element mismatch aborts the pull. `"skip"`
tolerates a bad element instead — but see the checkpoint guarantee below; it is not
an authorization mechanism and must not be used to silently drop unverified ops.

## Authorization

`authorPubkey` proves a **signature, not authorization**. WAL gives you the hooks;
the policy is yours:

- **`isAuthorizedWriter(pub)`** — gate which authors' op-batches a reader accepts.
- **`isSnapshotAuthor(pub)`** — gate who may produce an adopted snapshot.

Where the authorized-writer set lives (a signed member list? keyring epoch
recipients?), who maintains it, and how a reader fetches **historical** membership
are deployment decisions. Recommend cap-cert `kind: "device"` / `"member"`; scope
or forbid `audience` (it binds no subject).

Two **deliberate regressions vs. the merged-document model** a chooser must accept:

- **No field-level write authorization.** The merged model's `fieldPermissions`
  key on top-level fields of `data`, which for an op-batch is an opaque CRDT/
  ciphertext envelope — so it is a silent no-op, and there is no server-side fold to
  re-impose it. **Any holder of `writeRole` can LWW-overwrite any field,
  mass-tombstone a list, or delete any map key.** If per-path authorization is
  required, enforce it inside the client fold (every reader rejecting ops whose
  author lacks a signed, path-scoped grant) — it cannot be enforced server-side
  under `delegated`.
- **Authorization over time is non-retroactive.** A revoked writer's past ops stay
  validly signed and keep driving convergence; there is no trusted logical clock to
  gate "authorized-at-op-time". Closing this needs ops carrying a signed cap-cert
  reference (checked against `nbf`/`exp` + revocation) and/or trusted-role
  checkpoints that re-attest the authorized set.

## Truncation, rollback & replay

- **Forgery / reordering.** The server cannot forge ops (Ed25519) and cannot lower
  an element's `ts` below an existing one (`appendItem` is strictly monotonic), so
  it cannot back-date below a snapshot cutoff. Reordering is harmless
  (commutativity + the in-payload causal clock).
- **Replay.** A verbatim re-append of an old signed batch re-verifies (the signature
  omits `ts`), so a hostile server can resurface a superseded batch as a new tail.
  Convergence safety rests **entirely on op idempotence** — re-applying any in-scope
  op is a provable no-op. "Every op is idempotent under verbatim replay at a higher
  `ts`" is a tested security invariant.
- **Per-writer sequence.** Each batch carries a signed, per-author monotonic `seq`.
  A reader detects a gap (`detectedGaps()`), reconciled against a snapshot's
  `writerSeq` baseline so pruned-below-snapshot ops are not flagged. Set
  **`strictSequence: true`** to fail closed on a gap (it throws independent of
  `onAuthorError`). Honest limits: it catches truncation *within a writer's seen
  sequence*; it cannot by itself detect truncation of a writer's newest tail (nothing
  bounds the tail above the last snapshot's `writerSeq`) — that needs an out-of-band
  high-water mark.

### Skip-path checkpoint safety

Under `onAuthorError: "skip"`, the resume checkpoint only advances across a
**contiguous prefix of verified elements**. A skipped (unverified) element does not
move the checkpoint past it, so a malicious server cannot inject one bad element to
permanently suppress the honest ops that follow — later good elements are still
folded, and re-fetched/re-folded idempotently on the next pull.

## Snapshot trust

A compromised snapshot-role identity can assert false state **or censor by
omission** (fold a chosen subset, dropping a target writer's ops, and still produce
a validly-signed snapshot — `writerSeq` does not help, the same role authors it).
Mitigations:

- **`re-derive`** treats the snapshot as a hint and compares the full re-folded
  state against it (`snapshotVerified`); it is the only posture that resists a
  malicious-but-authorized producer.
- **`trust-retain-tail`** keeps `retainTailN` recent elements independently
  re-verifiable.
- Tightly scope the snapshot role via cap-certs.

Note `trust` delegates full integrity to the snapshot producer: its `writerSeq` /
`uptoTs` are adopted verbatim, so a compromised producer can blind a `trust` reader.
Steer security-sensitive readers to `re-derive`.

## Encryption integration

No new crypto primitives, but the op-log changes the AEAD workload:

- **AEAD invocation budget.** A high-frequency op-log drives the **per-CEK** seal
  count up (aggregated across writers/documents sharing a keyring). AES-256-GCM with
  random IVs must stay well below 2³² invocations per key. A production deployment
  should bound this — rotate the CEK on a seal-count budget, or derive a per-batch
  subkey. (The library does not yet trigger seal-count rotation; treat it as a
  keyring/server configuration concern.)
- **Epoch rotation.** New batches seal under the current epoch; historical batches
  keep their `_epoch`. As long as the keyring retains old epochs, the full log stays
  decryptable. A snapshot taken just after rotation lets newly-added recipients
  bootstrap without old-epoch keys. Defend against epoch downgrade with the keyring
  `minEpoch` guard.
- **No forward secrecy; re-seal amplifies compromise.** Old CEKs are retained
  indefinitely (replay needs them), so a leaked CEK exposes all of that epoch's ops
  permanently. A snapshot re-seals whole-history plaintext under the **current**
  epoch — treat each snapshot as an intentional **declassification** to
  current-epoch key-holders.

## Confidentiality & metadata

Plaintext never reaches the server, but the op-log leaks **more metadata** than a
merged document under E2EE — a real regression to accept:

- **Per-author timeline.** Each element carries a **cleartext `authorPubkey`** and a
  server `ts`, so an observer reconstructs a per-author activity timeline and
  collaboration graph without breaking encryption. Inherent while `authorPubkey` is
  cleartext.
- **Op-batch sizes leak op *type*.** AES-GCM doesn't pad, so a one-char keystroke vs.
  a structural/delete op produce distinguishable sizes. Pad/bucket sealed batches for
  size-sensitive deployments; debouncing blurs but timing still leaks.
- **`producedBy` + snapshot cadence/size** deanonymize the privileged snapshot role.
- **Right to erasure** is hard: append-only + immutable + a durable cleartext
  `authorPubkey` mean a CRDT "delete" only tombstones; true erasure needs
  snapshot-with-subject-removed + compaction (not yet implemented) and still cannot
  retract author metadata the server already observed.

## Threat model summary

| Adversary | Can | Cannot (given the mitigations) |
|---|---|---|
| Honest-but-curious server | Read all metadata: element count, op-batch sizes (→ op-type class), `ts` cadence, cleartext `authorPubkey`, snapshot cadence/size | Read plaintext under `delegated`; forge ops |
| Malicious server / network | Reorder delivery, withhold/truncate the tail, roll back to a prefix, replay old signed batches | Forge ops; lower an element's `ts`; back-date below a snapshot cutoff; suppress honest ops after a skipped one (skip-path checkpoint) |
| Malicious authorized writer | Append any op to any path (no field-level authz); flood ops; bloat tombstones | Impersonate another author; write a collection it has no `writeRole` on |
| Malicious snapshot role | Assert false state; censor by omission | Forge op signatures; be accepted by a `re-derive` reader on retained history |
| Compromised reader device | Exfiltrate all decryptable history + every epoch CEK it holds | — |
| Revoked member | Retain pre-rotation history; past ops stay validly signed | Read post-rotation batches |
