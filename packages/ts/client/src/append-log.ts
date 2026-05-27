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
 * the author fields — so the shape is uniform and re-seedable.
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

export interface AppendLogCursorOptions {
  client: StarfishClient
  /** Pull endpoint path, e.g. `"/pull/events"`. */
  pullPath: string
  /** Array field name in the pulled document. Defaults to `"items"`. */
  appendField?: string
  /**
   * Warm-start seed: raw envelopes the caller persisted last session. The
   * cursor adopts them verbatim (never re-decrypts/re-verifies them) and
   * derives its initial checkpoint from their max `ts`.
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
   * Caveat: a returned / `getItems()` element then holds DECRYPTED `data` but an
   * `authorSignature` computed over the stored CIPHERTEXT — they no longer match,
   * so do NOT re-verify a decrypted element with `verifyAppendAuthor`. The cursor
   * already verified it (over the ciphertext) at pull time when `verifyAuthor` is
   * on; `authorPubkey` is retained for identity.
   */
  encryptor?: Encryptor
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
 * elements; persistence is a round-trip of `getItems()` (see the `encryptor`
 * caveat when decrypting):
 * ```ts
 * const log = new AppendLogCursor({ client, pullPath: "/pull/events",
 *   initialItems: await store.load() })
 * const fresh = await log.pull()
 * await store.save(log.getItems())
 * ```
 */
export class AppendLogCursor {
  private readonly client: StarfishClient
  private readonly pullPath: string
  private readonly appendField: string
  private readonly encryptor?: Encryptor
  private readonly verifyAuthor?: boolean | AuthorVerifier
  private readonly documentKey: string
  private readonly logger?: SyncLogger
  private readonly loggerName: string

  private readonly items: AppendElement[]
  private lastCheckpoint: number

  constructor(options: AppendLogCursorOptions) {
    this.client = options.client
    this.pullPath = options.pullPath
    this.appendField = options.appendField ?? "items"
    this.encryptor = options.encryptor
    this.verifyAuthor = options.verifyAuthor
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
   * append them to the local log, and return ONLY the newly-fetched batch.
   *
   * Atomic: the batch is fully verified and decrypted into a local before any
   * state mutation, so a verify/decrypt failure throws without advancing the
   * checkpoint past elements that could never be re-fetched.
   *
   * Not safe to call concurrently: like `SyncManager.pull`, overlapping calls
   * read the same checkpoint and would fetch — and append — the same window twice.
   */
  async pull(): Promise<AppendElement[]> {
    this.logger?.pullStart(this.loggerName)
    const start = performance.now()
    try {
      const since = this.lastCheckpoint
      // Omit `since` on cold start so the request carries no `?checkpoint=`.
      const opts: AppendPullOptions =
        since > 0 ? { appendField: this.appendField, since } : { appendField: this.appendField }
      const raw = await this.client.pull<AppendElement>(this.pullPath, opts)

      const batch: AppendElement[] = []
      let maxTs = since
      for (const el of raw) {
        // Defensive: guard a misbehaving/mocked server from making us
        // double-append a held element. Gated on `since > 0` to mirror the
        // server (which only filters when checkpoint > 0): on a cold start
        // `since` is 0 and we must NOT drop a legitimate `ts: 0` first element.
        if (since > 0 && el.ts <= since) continue
        this.verifyOne(el)
        const data = this.encryptor ? await this.encryptor.decrypt(el.data) : el.data
        const out: AppendElement = { ts: el.ts, data }
        if (el.authorPubkey !== undefined) out.authorPubkey = el.authorPubkey
        if (el.authorSignature !== undefined) out.authorSignature = el.authorSignature
        batch.push(out)
        if (el.ts > maxTs) maxTs = el.ts
      }

      this.items.push(...batch)
      this.lastCheckpoint = maxTs
      this.logger?.pullSuccess(this.loggerName, Math.round(performance.now() - start))
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

  /** The full accumulated log (a shallow copy), in `ts` order. */
  getItems(): AppendElement[] {
    return [...this.items]
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
