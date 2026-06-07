/**
 * Read-modify-write a document with hash-CAS conflict retry.
 *
 * The everyday way to atomically edit a synced document: pull the current
 * version, apply a pure `mutator` to its data, push the result with the read
 * hash, and retry on a {@link ConflictError} (a concurrent writer moved the hash)
 * by re-reading FRESH server state and re-applying the mutator. A missing
 * document (404) is surfaced to the mutator as `{ data: null, hash: null }` so it
 * can create the doc on first write.
 *
 * This replaces the ad-hoc `for (attempt…) { pull; mutate; try push catch
 * ConflictError }` loop that applications otherwise hand-roll around every
 * editable doc. The `mutator` MUST be idempotent — it re-runs on each retry — and
 * returns `null` to signal a no-op (nothing changed; skip the write).
 */
import { StarfishClient } from "./client.js"
import { ConflictError, StarfishHttpError } from "./types.js"

/** The current state handed to a {@link DocMutator}: the document data (or `null`
 *  when the doc does not exist yet) and the hash to base the next push on. */
export interface DocState<T> {
  data: T | null
  hash: string | null
}

/**
 * Pure transform from the current document to the next. Return the full next
 * document body to write, or `null` for a no-op (the write is skipped). Runs once
 * per attempt on freshly-pulled state, so it must be idempotent.
 */
export type DocMutator<T> = (cur: DocState<T>) => T | null

export interface MutateDocOptions {
  /** Max push attempts before a persistent conflict propagates. Default 3. */
  maxAttempts?: number
}

/**
 * Atomically read-modify-write the document at `path`. Returns the document that
 * was written, or `null` if the mutator signalled a no-op. Throws the underlying
 * error on a non-conflict failure, or a {@link ConflictError} if every attempt
 * raced and lost.
 */
export async function mutateDoc<T extends Record<string, unknown> = Record<string, unknown>>(
  client: StarfishClient,
  path: string,
  mutator: DocMutator<T>,
  options: MutateDocOptions = {},
): Promise<T | null> {
  const maxAttempts = Math.max(1, options.maxAttempts ?? 3)
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    let data: T | null = null
    let hash: string | null = null
    try {
      const res = await client.pull(path)
      data = (res.data as T) ?? null
      hash = res.hash ?? null
    } catch (err) {
      // A 404 means the doc does not exist yet — hand the mutator a null state so
      // it can create it. Any other HTTP/transport error propagates.
      if (!(err instanceof StarfishHttpError) || err.status !== 404) throw err
    }
    const next = mutator({ data, hash })
    if (next === null) return null
    try {
      await client.push(path, next, hash)
      return next
    } catch (err) {
      if (err instanceof ConflictError && attempt < maxAttempts - 1) continue
      throw err
    }
  }
  // Unreachable: the final attempt either returns or re-throws above.
  throw new ConflictError()
}
