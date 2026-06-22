/**
 * CAS (Compare-And-Swap) retry helper.
 *
 * Wraps a read-modify-write block in a retry loop, absorbing `ConflictError`
 * (HTTP 409) up to `MAX_ATTEMPTS` times before re-throwing. Each retry
 * re-reads the current server state before re-running the block.
 */
import { ConflictError } from "@drakkar.software/starfish-client"

const MAX_ATTEMPTS = 3

/**
 * Run `fn` up to {@link MAX_ATTEMPTS} times, retrying on {@link ConflictError}.
 * `fn` should: (1) pull the current doc, (2) compute the new state, (3) push it.
 * On conflict the server rejected the push because the doc changed under us;
 * re-running `fn` from scratch will pull the freshest state and try again.
 *
 * Throws on the first non-conflict error, or after all retries are exhausted.
 */
export async function runCas<T>(fn: () => Promise<T>): Promise<T> {
  let attempt = 0
  while (true) {
    try {
      return await fn()
    } catch (err) {
      if (err instanceof ConflictError && ++attempt < MAX_ATTEMPTS) continue
      throw err
    }
  }
}
