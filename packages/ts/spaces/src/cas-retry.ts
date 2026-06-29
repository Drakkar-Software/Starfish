/**
 * CAS (Compare-And-Swap) retry helper.
 *
 * Wraps a read-modify-write block in a retry loop, absorbing `ConflictError`
 * (HTTP 409) up to `MAX_ATTEMPTS` times before re-throwing. Each retry
 * re-reads the current server state before re-running the block.
 */
import { ConflictError } from "@drakkar.software/starfish-client"

const MAX_ATTEMPTS = 3

/** Hint passed to the `fn` callback on each CAS attempt. */
export interface CasHint {
  /**
   * Authoritative server hash from the previous 409 conflict response, or `""`
   * on the first attempt.  Use as `baseHash` instead of (or in addition to) the
   * pulled hash to avoid a second stale read when the storage backend has a
   * read-after-write consistency gap (e.g. Garage RF>1 replication lag).
   */
  currentHash: string
}

/**
 * Run `fn` up to {@link MAX_ATTEMPTS} times, retrying on {@link ConflictError}.
 * `fn` should: (1) pull the current doc, (2) compute the new state, (3) push it.
 * On conflict the server rejected the push because the doc changed under us;
 * re-running `fn` from scratch will pull the freshest state and try again.
 *
 * The {@link CasHint} passed to `fn` carries the authoritative `currentHash`
 * from the previous conflict response.  Callers that know the storage backend
 * may return stale reads can use it to skip a second unreliable pull.
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
      return await fn({ currentHash })
    } catch (err) {
      if (err instanceof ConflictError && ++attempt < MAX_ATTEMPTS) {
        currentHash = err.currentHash
        continue
      }
      throw err
    }
  }
}
