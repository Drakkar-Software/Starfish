/**
 * Causal clock for the WAL CRDT.
 *
 * Every CRDT op carries a {@link Clock}: a Lamport counter `c` plus a stable,
 * per-session `replicaId` `r`. The pair `(c, r)` defines a **total order with no
 * ties** — the load-bearing convergence obligation:
 * two concurrent ops can share a counter `c`, but never a `replicaId`, so the
 * LWW tie-break is always decidable and identical in TypeScript and Python.
 *
 * The clock lives **inside** the (optionally encrypted) op payload, so the
 * server never observes or tampers with convergence ordering — its assigned
 * element `ts` is used only for incremental pulls, never for conflict
 * resolution.
 */

/** A Lamport counter (`c`) tie-broken by a stable replica id (`r`). */
export interface Clock {
  /** Monotonic Lamport counter, advanced locally before each op. */
  c: number
  /** Stable, unique-per-session replica id (see {@link deriveReplicaId}). */
  r: string
}

/**
 * Compare two strings by Unicode code point (matching Python's default string
 * ordering and the protocol's `stableStringify` key sort). JavaScript's default
 * comparison is by UTF-16 code unit, which disagrees for non-BMP characters, so
 * a replica-id tie-break must use this to stay byte-identical cross-language.
 */
export function compareCodePoints(a: string, b: string): number {
  const ai = a[Symbol.iterator]()
  const bi = b[Symbol.iterator]()
  for (;;) {
    const x = ai.next()
    const y = bi.next()
    if (x.done && y.done) return 0
    if (x.done) return -1
    if (y.done) return 1
    const cx = x.value.codePointAt(0)!
    const cy = y.value.codePointAt(0)!
    if (cx !== cy) return cx - cy
  }
}

/**
 * Total order over clocks: counter first, replica id second. Returns a negative
 * number if `a < b`, positive if `a > b`, and `0` only when the clocks are
 * **identical** — which, given unique replica ids, means it is literally the
 * same op (so an idempotent replay folds to a no-op).
 */
export function compareClocks(a: Clock, b: Clock): number {
  if (a.c !== b.c) return a.c - b.c
  return compareCodePoints(a.r, b.r)
}

/** True iff clock `a` strictly dominates `b` in the total order. */
export function clockGreater(a: Clock, b: Clock): boolean {
  return compareClocks(a, b) > 0
}

/**
 * A monotonic Lamport clock for one replica. `tick()` returns the next clock to
 * stamp on a locally-produced op; `observe()` advances the counter past a clock
 * seen on an incoming op so future local ops causally follow it.
 */
export class LamportClock {
  private counter: number

  constructor(
    readonly replicaId: string,
    start = 0,
  ) {
    this.counter = start
  }

  /** Current counter value (the highest stamped/observed so far). */
  get value(): number {
    return this.counter
  }

  /** Advance and return the next clock to stamp on a local op. */
  tick(): Clock {
    this.counter += 1
    return { c: this.counter, r: this.replicaId }
  }

  /** Advance the counter past an observed clock (Lamport receive rule). */
  observe(clock: Clock): void {
    if (clock.c > this.counter) this.counter = clock.c
  }
}

/**
 * Derive a stable, unique replica id from the author's Ed25519 public key (hex)
 * and a per-session nonce. A single device runs multiple tabs/sessions, so the
 * device key alone is **not** unique; the nonce disambiguates
 * concurrent sessions of the same author. The id is opaque to the CRDT — only
 * its byte-identity and uniqueness matter.
 */
export function deriveReplicaId(authorPubHex: string, sessionNonce: string): string {
  return `${authorPubHex}:${sessionNonce}`
}
