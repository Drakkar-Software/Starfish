import {
  DEFAULT_ALG,
  verifyAppendAuthor,
  type Alg,
  type Encryptor,
} from "@drakkar.software/starfish-protocol"
import type { StarfishClient, AppendPullOptions } from "./client.js"
import type { SyncLogger } from "./logger.js"

/** The `/pull/` action prefix; mirrors `PUSH_PATH_PREFIX` for the read side. */
const PULL_PATH_PREFIX = "/pull/"

/** The storage `documentKey` for a pull `path`: the path with the `/pull/`
 *  action prefix stripped (the namespace lives only in the URL). The author
 *  signature binds to this key, so a reader re-derives it the same way the
 *  writer did from `/push/…`. */
function stripPullPrefix(path: string): string {
  return path.startsWith(PULL_PATH_PREFIX) ? path.slice(PULL_PATH_PREFIX.length) : path
}

/**
 * A single stored element of an append-only collection, exactly as returned by
 * `client.pull(path, { appendField })`. `ts` is the server-assigned, strictly
 * increasing element timestamp; `data` is the payload (plaintext under the
 * `"none"` encryption mode, the opaque encryptor wrapper under `"delegated"`).
 *
 * When an {@link AppendLogCursor} is given an `encryptor`, the elements it
 * stores and returns carry the **decrypted** `data` while preserving `ts` and
 * the author fields — so the shape is uniform and re-seedable. The exception is
 * `persistEncrypted` mode (see {@link AppendLogCursorOptions.persistEncrypted}),
 * where the stored elements keep their **ciphertext** `data` (E2EE-safe to
 * persist) and decryption happens only on read via {@link AppendLogCursor.pull}
 * and {@link AppendLogCursor.getDecryptedItems}.
 */
export interface AppendElement {
  ts: number
  data: Record<string, unknown>
  authorPubkey?: string
  authorSignature?: string
}

/** Per-element author-signature verification policy for {@link AppendLogCursor}. */
export interface AuthorVerifier {
  /** If set, every element's `authorPubkey` MUST equal this key (compared as
   *  case-insensitive hex), else the pull fails. Omit to accept any signing key
   *  (verify only that the signature is valid for the element's self-declared
   *  `authorPubkey` — see the `verifyAuthor` note on restricting authors). */
  expectedAuthorPubkey?: string
  /** Signing suite the signatures were produced under. Defaults to `DEFAULT_ALG`. */
  alg?: Alg
}

/**
 * What to do when a single element fails verification or decryption during a
 * {@link AppendLogCursor.pull} (or {@link AppendLogCursor.getDecryptedItems}).
 *
 * - `"throw"` (default): the pull is **atomic** — the first bad element throws
 *   and NO state is mutated, so the checkpoint never advances past an element
 *   that could not be re-fetched. Use when every element must be readable.
 * - `"skip"`: a bad element is dropped from the returned/decrypted batch and the
 *   checkpoint still **advances past it** (so it is never re-fetched), letting one
 *   poison element fail without blanking the whole log. Intended for tolerating
 *   **decrypt** failures in a multi-writer / E2EE log (keyring skew, a foreign or
 *   corrupt element). SECURITY NOTE: `"skip"` ALSO silently drops elements that
 *   fail *author* verification rather than failing loudly — so if you also need
 *   strict authorship, set `verifyAuthor.expectedAuthorPubkey` (single author) or
 *   check each element's `authorPubkey` against your authorized set after pull.
 */
export type ElementErrorPolicy = "throw" | "skip"

export interface AppendLogCursorOptions {
  client: StarfishClient
  /** Pull endpoint path, e.g. `"/pull/events"`. */
  pullPath: string
  /** Array field name in the pulled document. Defaults to `"items"`. */
  appendField?: string
  /**
   * Warm-start seed: raw envelopes the caller persisted last session. The
   * cursor adopts them verbatim and derives its initial checkpoint from their
   * max `ts`. Under the default mode they are taken as already-decrypted (and
   * never re-decrypted/re-verified); under `persistEncrypted` they are the
   * persisted **ciphertext** and are decrypted on read (see `persistEncrypted`).
   */
  initialItems?: AppendElement[]
  /**
   * Explicit checkpoint-only seed (ms). Resume incrementally without
   * rehydrating history. When given together with `initialItems`, it must be
   * `>= max(ts of initialItems)` (a lower value would re-fetch held items).
   */
  since?: number
  /**
   * When set, each freshly-pulled element's `.data` is decrypted via this
   * encryptor (the `ts`/author fields are preserved). Author verification, when
   * enabled, runs over the original (pre-decryption) `data`.
   *
   * Caveat (default mode): a returned / `getItems()` element then holds DECRYPTED
   * `data` but an `authorSignature` computed over the stored CIPHERTEXT — they no
   * longer match, so do NOT re-verify a decrypted element with `verifyAppendAuthor`.
   * The cursor already verified it (over the ciphertext) at pull time when
   * `verifyAuthor` is on; `authorPubkey` is retained for identity. (Under
   * `persistEncrypted` the stored elements keep their ciphertext, so this caveat
   * does not apply to `getItems()`.)
   */
  encryptor?: Encryptor
  /**
   * Per-element failure policy for verification/decryption. Defaults to
   * `"throw"` (atomic pull — preserves the pre-existing behavior). See
   * {@link ElementErrorPolicy}.
   */
  onElementError?: ElementErrorPolicy
  /**
   * Keep the **ciphertext** form of each element in the cursor's accumulated log
   * instead of the decrypted form (requires `encryptor`; a no-op without one,
   * since plaintext is already its own stored form). This makes
   * {@link AppendLogCursor.getItems} return the persistable ciphertext — safe to
   * write to disk for an end-to-end-encrypted log without leaking plaintext at
   * rest — while {@link AppendLogCursor.pull} still returns the freshly-decrypted
   * batch and {@link AppendLogCursor.getDecryptedItems} returns the full log
   * decrypted (for warm-start rendering). Defaults to `false` (store decrypted).
   */
  persistEncrypted?: boolean
  /**
   * `true` to verify every element's author signature, or a policy object.
   *
   * This verifies the signature is valid for the element's self-declared
   * `authorPubkey` — it does NOT by itself restrict WHICH authors are accepted.
   * To restrict authorship, set `expectedAuthorPubkey` (single author), or check
   * each `el.authorPubkey` against your own authorization source (keyring /
   * member list / cap allow-list) after pull — for a multi-writer log, the
   * authorized set lives there and changes over time, not here.
   *
   * The signature covers `data` + the document key, but NOT `ts`: a malicious
   * server cannot forge content, but can reorder or re-timestamp authentic
   * elements, so trust `ts` only as far as you trust the server.
   */
  verifyAuthor?: boolean | AuthorVerifier
  /** Structured logger for pull events. */
  logger?: SyncLogger
  /** Name passed to logger methods (default: derived from `pullPath`). */
  loggerName?: string
}

/** Thrown when an append element's author signature fails verification. */
export class AppendAuthorError extends Error {
  constructor(public readonly ts: number) {
    super(`append element author verification failed (ts=${ts})`)
    this.name = "AppendAuthorError"
  }
}

/** Largest `ts` among `items`, or `0` when empty. The checkpoint for an
 *  append-only log is exactly this — the server returns elements with
 *  `ts > checkpoint`, and element timestamps are strictly increasing. */
export function checkpointOf(items: readonly { ts: number }[]): number {
  let max = 0
  for (const it of items) if (it.ts > max) max = it.ts
  return max
}

/** Copy the optional author fields from `src` onto a fresh element with `data`. */
function withAuthor(ts: number, data: Record<string, unknown>, src: AppendElement): AppendElement {
  const out: AppendElement = { ts, data }
  if (src.authorPubkey !== undefined) out.authorPubkey = src.authorPubkey
  if (src.authorSignature !== undefined) out.authorSignature = src.authorSignature
  return out
}

/**
 * A stateful cursor over an append-only collection. It owns the accumulated
 * array of elements and pulls only what is new: each {@link pull} derives the
 * checkpoint from the last element it holds and asks the server for elements
 * with a greater `ts`.
 *
 * This is the incremental, stateful counterpart to the deliberately stateless
 * `client.pull(path, { appendField, since })`, and the sibling of
 * {@link SyncManager} for append-only logs (no merge / push-conflict
 * machinery — a log only grows).
 *
 * The cursor accumulates every pulled element in memory; for an unboundedly
 * large log, pull a bounded window with raw `client.pull(path, { last })` instead.
 *
 * Cold start (nothing persisted) — first `pull()` fetches the whole collection:
 * ```ts
 * const log = new AppendLogCursor({ client, pullPath: "/pull/events" })
 * const all = await log.pull()
 * ```
 * Warm start (resume from persisted data) — first `pull()` fetches only newer
 * elements; persistence is a round-trip of `getItems()`:
 * ```ts
 * const log = new AppendLogCursor({ client, pullPath: "/pull/events",
 *   initialItems: await store.load() })
 * const fresh = await log.pull()
 * await store.save(log.getItems())
 * ```
 * Warm start for an **E2EE** log — persist ciphertext, render decrypted:
 * ```ts
 * const log = new AppendLogCursor({ client, pullPath: "/pull/streamchat",
 *   encryptor, persistEncrypted: true, onElementError: "skip",
 *   initialItems: await store.load() })           // ciphertext from disk
 * const history = await log.getDecryptedItems()    // render persisted history
 * const fresh = await log.pull()                   // decrypted delta
 * await store.save(log.getItems())                 // ciphertext back to disk
 * ```
 */
export class AppendLogCursor {
  private readonly client: StarfishClient
  private readonly pullPath: string
  private readonly appendField: string
  private readonly encryptor?: Encryptor
  private readonly verifyAuthor?: boolean | AuthorVerifier
  private readonly onElementError: ElementErrorPolicy
  private readonly persistEncrypted: boolean
  private readonly documentKey: string
  private readonly logger?: SyncLogger
  private readonly loggerName: string

  private readonly items: AppendElement[]
  private lastCheckpoint: number

  /** Tail of the serialized pull chain. Concurrent `pull()` calls queue behind
   *  it so each runs against the checkpoint the previous one advanced — no two
   *  overlapping fetches read the same checkpoint and double-append a window. */
  private pullChain: Promise<unknown> = Promise.resolve()

  constructor(options: AppendLogCursorOptions) {
    this.client = options.client
    this.pullPath = options.pullPath
    this.appendField = options.appendField ?? "items"
    this.encryptor = options.encryptor
    this.verifyAuthor = options.verifyAuthor
    this.onElementError = options.onElementError ?? "throw"
    this.persistEncrypted = options.persistEncrypted ?? false
    this.documentKey = stripPullPrefix(options.pullPath)
    this.logger = options.logger
    this.loggerName =
      options.loggerName ?? options.pullPath.split("/").filter(Boolean).pop() ?? options.pullPath

    const seed = options.initialItems ?? []
    const seedCheckpoint = checkpointOf(seed)
    if (options.since != null) {
      if (options.since < 0) throw new Error("since must be non-negative")
      if (options.since < seedCheckpoint) {
        throw new Error("since must be >= the max ts of initialItems")
      }
      this.lastCheckpoint = options.since
    } else {
      this.lastCheckpoint = seedCheckpoint
    }
    this.items = [...seed]
  }

  /**
   * Fetch elements newer than the current checkpoint, verify + decrypt them,
   * append them to the local log, and return ONLY the newly-fetched batch
   * (decrypted when an `encryptor` is set).
   *
   * Atomic under `onElementError: "throw"` (the default): the batch is fully
   * verified and decrypted into a local before any state mutation, so a
   * verify/decrypt failure throws without advancing the checkpoint past elements
   * that could never be re-fetched. Under `"skip"`, a failing element is dropped
   * from the returned batch but the checkpoint still advances past it.
   *
   * Safe to call concurrently: overlapping calls are serialized internally, so
   * each runs against the checkpoint the previous one advanced (no double-fetch
   * of the same window). The next pull after one completes will pick up anything
   * that arrived in between.
   */
  async pull(): Promise<AppendElement[]> {
    // Chain onto the previous pull (whether it resolved or rejected) so calls
    // run one-at-a-time against the latest checkpoint. `pullChain` swallows
    // outcomes to stay alive; the caller still sees this call's real result.
    const run = this.pullChain.then(
      () => this.doPull(),
      () => this.doPull(),
    )
    this.pullChain = run.then(
      () => undefined,
      () => undefined,
    )
    return run
  }

  private async doPull(): Promise<AppendElement[]> {
    this.logger?.pullStart(this.loggerName)
    const start = performance.now()
    try {
      const since = this.lastCheckpoint
      // Omit `since` on cold start so the request carries no `?checkpoint=`.
      const opts: AppendPullOptions =
        since > 0 ? { appendField: this.appendField, since } : { appendField: this.appendField }
      const raw = await this.client.pull<AppendElement>(this.pullPath, opts)

      const batch: AppendElement[] = [] // decrypted, returned to the caller
      const stored: AppendElement[] = [] // what we keep in `items` (cipher- or plaintext)
      let maxTs = since
      let skipped = 0
      for (const el of raw) {
        // Defensive: guard a misbehaving/mocked server from making us
        // double-append a held element. Gated on `since > 0` to mirror the
        // server (which only filters when checkpoint > 0): on a cold start
        // `since` is 0 and we must NOT drop a legitimate `ts: 0` first element.
        if (since > 0 && el.ts <= since) continue
        // Advance past every windowed element BEFORE verify/decrypt so a skipped
        // element still moves the checkpoint and is never re-fetched.
        if (el.ts > maxTs) maxTs = el.ts

        let decrypted: AppendElement | null = null
        try {
          this.verifyOne(el)
          const data = this.encryptor ? await this.encryptor.decrypt(el.data) : el.data
          decrypted = withAuthor(el.ts, data, el)
        } catch (err) {
          // "throw" rethrows here, before any state mutation below — atomic.
          if (this.onElementError !== "skip") throw err
          skipped++
        }

        if (this.persistEncrypted) {
          // Keep the original ciphertext envelope (even for a skipped element:
          // it is valid data we simply cannot read now — a later key might).
          stored.push(withAuthor(el.ts, el.data, el))
        } else if (decrypted) {
          stored.push(decrypted)
        }
        if (decrypted) batch.push(decrypted)
      }

      this.items.push(...stored)
      this.lastCheckpoint = maxTs
      this.logger?.pullSuccess(
        this.loggerName,
        Math.round(performance.now() - start),
        skipped > 0 ? { skippedCount: skipped } : undefined,
      )
      return batch
    } catch (err) {
      this.logger?.pullError(this.loggerName, err instanceof Error ? err.message : String(err))
      throw err
    }
  }

  /** Verify a single element's author signature over its RAW (pre-decryption)
   *  `data`. Throws {@link AppendAuthorError} on any failure. No-op when
   *  verification is disabled. */
  private verifyOne(el: AppendElement): void {
    if (!this.verifyAuthor) return
    const policy: AuthorVerifier = typeof this.verifyAuthor === "object" ? this.verifyAuthor : {}
    const { authorPubkey, authorSignature } = el
    if (!authorPubkey || !authorSignature) throw new AppendAuthorError(el.ts)
    // Public keys are hex, which is case-insensitive — compare normalized so a
    // caller passing a differently-cased `expectedAuthorPubkey` isn't falsely rejected.
    if (
      policy.expectedAuthorPubkey &&
      authorPubkey.toLowerCase() !== policy.expectedAuthorPubkey.toLowerCase()
    ) {
      throw new AppendAuthorError(el.ts)
    }
    const ok = verifyAppendAuthor(
      this.documentKey,
      el.data,
      authorPubkey,
      authorSignature,
      policy.alg ?? DEFAULT_ALG,
    )
    if (!ok) throw new AppendAuthorError(el.ts)
  }

  /** The full accumulated log (a shallow copy), in `ts` order. Under
   *  `persistEncrypted` these carry CIPHERTEXT `data` (persist them as-is, then
   *  re-seed via `initialItems`); otherwise they carry decrypted/plaintext data. */
  getItems(): AppendElement[] {
    return [...this.items]
  }

  /**
   * The full accumulated log, DECRYPTED — for rendering warm-started history in
   * `persistEncrypted` mode (where {@link getItems} holds ciphertext). Honors
   * `onElementError` (a `"skip"` cursor drops elements it cannot read). When the
   * cursor has no `encryptor`, or is not in `persistEncrypted` mode, the held
   * elements are already plaintext/decrypted and are returned as-is.
   */
  async getDecryptedItems(): Promise<AppendElement[]> {
    const snapshot = [...this.items]
    if (!this.encryptor || !this.persistEncrypted) return snapshot
    const out: AppendElement[] = []
    for (const el of snapshot) {
      try {
        this.verifyOne(el)
        const data = await this.encryptor.decrypt(el.data)
        out.push(withAuthor(el.ts, data, el))
      } catch (err) {
        if (this.onElementError !== "skip") throw err
      }
    }
    return out
  }

  /** The current checkpoint: the max `ts` held (the next pull's `since`). `0`
   *  when nothing has been pulled or seeded. */
  getCheckpoint(): number {
    return this.lastCheckpoint
  }

  /** Restore the checkpoint without seeding items — for persistence layers that
   *  store only the checkpoint. Used to resume incrementally across restarts.
   *  Rejects a value below the max `ts` already held: rewinding would make the
   *  next pull re-deliver, and duplicate, elements the cursor already has. */
  setCheckpoint(ts: number): void {
    if (ts < checkpointOf(this.items)) {
      throw new Error("checkpoint must be >= the max ts already held")
    }
    this.lastCheckpoint = ts
  }
}
