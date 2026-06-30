/**
 * CAS (Compare-And-Swap) retry helper.
 *
 * Wraps a read-modify-write block in a retry loop, absorbing `ConflictError`
 * (HTTP 409) up to `MAX_ATTEMPTS` times before re-throwing. Each retry
 * re-reads the current server state before re-running the block.
 */
import { ConflictError } from "@drakkar.software/starfish-client"

const MAX_ATTEMPTS = 5
const MAX_BACKOFF_MS = 800

/** Hint passed to the `fn` callback on each CAS attempt. */
export interface CasHint {
  /**
   * Authoritative server hash from the previous 409 conflict response, or `""`
   * on the first attempt.  Use as `baseHash` instead of (or in addition to) the
   * pulled hash to avoid a second stale read when the storage backend has a
   * read-after-write consistency gap (e.g. Garage RF>1 replication lag).
   *
   * NOTE: some server deployments (e.g. the TypeScript sync server) return a
   * 409 body without a `currentHash`, so this value may be `""` even on retries.
   * Callers must not rely solely on this hint — always do a fresh pull on retry.
   */
  currentHash: string
  /**
   * Zero-indexed attempt counter: 0 on the first call, 1 on the first retry, etc.
   * Use to gate warm-cache-only paths to the first attempt and force a fresh
   * network pull on all subsequent attempts.
   */
  attempt: number
}

/**
 * Run `fn` up to {@link MAX_ATTEMPTS} times, retrying on {@link ConflictError}.
 * `fn` should: (1) pull the current doc, (2) compute the new state, (3) push it.
 * On conflict the server rejected the push because the doc changed under us;
 * re-running `fn` from scratch will pull the freshest state and try again.
 *
 * The {@link CasHint} passed to `fn` carries the authoritative `currentHash`
 * from the previous conflict response and the current `attempt` index.
 *
 * Existing zero-arg callbacks `async () => { ... }` remain valid — the hint
 * argument is ignored if the callback does not declare it.
 *
 * Throws on the first non-conflict error, or after all retries are exhausted.
 */
export async function runCas<T>(fn: (hint: CasHint) => Promise<T>): Promise<T> {
  let attempt = 0
  let currentHash = ""
  while (true) {
    try {
      return await fn({ currentHash, attempt })
    } catch (err) {
      if (err instanceof ConflictError && ++attempt < MAX_ATTEMPTS) {
        currentHash = err.currentHash
        // Jittered exponential backoff gives replicas time to converge before
        // the next attempt.  Mirrors the SyncManager.push loop in starfish-client.
        const base = Math.min(80 * Math.pow(2, attempt - 1), MAX_BACKOFF_MS)
        const jitter = Math.random() * base * 0.25
        await new Promise<void>((r) => setTimeout(r, base + jitter))
        continue
      }
      throw err
    }
  }
}
