/**
 * Keyring lifecycle helper — idempotent "ensure keyring exists and add recipient".
 *
 * The low-level `addCollectionRecipient` / `createKeyring` primitives give
 * consumers full control, but the overwhelming common case is:
 *
 * > "Given a collection path, make sure a keyring exists for it and that
 * >  this recipient can read it — creating the keyring on first use,
 * >  skipping if the recipient is already present, and retrying on a hash
 * >  conflict caused by a concurrent writer."
 *
 * `ensureKeyringRecipient` encodes that ordering invariant in one call so every
 * starfish consumer does not have to hand-roll the same CAS retry + benign-error
 * detection loop. The path layout (where the keyring doc lives relative to the
 * collection) is the caller's concern — pass `keyringPath` explicitly or rely
 * on the `keyringPathFor(collectionPath)` default.
 *
 * Design constraints:
 * - MUST create the keyring before adding a recipient (the keyring doc must
 *   contain at least one epoch entry before `addCollectionRecipient` can wrap
 *   a CEK for the new recipient).
 * - "Already present" errors are treated as success (idempotent).
 * - Hash conflicts (a concurrent write moved the doc hash) trigger a re-read
 *   and retry, up to `maxAttempts` (default 3).
 * - Any other error propagates immediately.
 *
 * @module starfish-keyring/ensure
 */

import type { StarfishClient } from "@drakkar.software/starfish-client"
import { ConflictError } from "@drakkar.software/starfish-client"
import { createKeyring } from "./keyring.js"
import { addRecipient as addCollectionRecipient, keyringPathFor } from "./recipients.js"
import type { RecipientRef, AdderKeys, RecipientMutationOpts } from "./recipients.js"

// ── helpers ───────────────────────────────────────────────────────────────────

/**
 * Return `true` when `err` indicates the recipient is ALREADY present in the
 * keyring. Server implementations and the `addRecipient` function in keyring.ts
 * phrase this in slightly different ways; we accept a range of patterns while
 * requiring at least one keyword so generic errors are NOT swallowed.
 */
function isAlreadyPresent(err: unknown): boolean {
  if (!(err instanceof Error)) return false
  return /already (present|a recipient|exists)|duplicate/i.test(err.message)
}

function getStatus(err: unknown): number {
  if (err != null && typeof err === "object" && "status" in err) {
    return (err as { status: number }).status
  }
  return 0
}

// ── public API ────────────────────────────────────────────────────────────────

/** Options for {@link ensureKeyringRecipient}. */
export interface EnsureKeyringRecipientOptions {
  /**
   * Path of the keyring document (e.g. from {@link keyringPathFor}).
   * Defaults to `keyringPathFor(collectionPath)` when omitted.
   * Override when your layout differs from the `<collection>/_keyring` convention.
   */
  keyringPath?: string
  /**
   * The adder's X25519 KEM **public** key (hex). Required only when the
   * keyring does not exist yet and must be created from scratch — the adder
   * is inserted as the initial epoch recipient so they can later unwrap the
   * CEK. If omitted and the keyring is missing, the create step is skipped
   * and `addCollectionRecipient` will throw its usual "no keyring exists" error.
   *
   * Callers who own the collection typically have this value alongside
   * `AdderKeys.kemPriv`; it is deliberately kept out of `AdderKeys` (to avoid
   * changing a stable shared type) but required here on first-creation paths.
   */
  adderKemPub?: string
  /**
   * Max CAS attempts on hash conflict. Default `3`.
   * Each retry re-reads the keyring before re-attempting the write.
   */
  maxAttempts?: number
  /**
   * Additional options forwarded to {@link addCollectionRecipient}
   * (e.g. `trustedAdders`).
   *
   * **IMPORTANT**: `trustedAdders` is required by `addCollectionRecipient`
   * to protect against CEK-substitution attacks (the adder's wrapped key
   * entry is self-attesting). Pass at minimum `[adder.edPub]` when the
   * adder is the sole/trusted grantor.
   */
  recipientOpts?: RecipientMutationOpts
}

/**
 * Ensure a keyring exists for `collectionPath` and that `recipient` can read it.
 *
 * Steps (ordered to satisfy the keyring invariant):
 * 1. Attempt to read the current keyring. If it does not exist (404) AND
 *    `opts.adderKemPub` was provided, create the keyring with the adder as
 *    the first epoch recipient.
 * 2. Add `recipient` as a keyring recipient (wrapping the CEK for their KEM key).
 * 3. On "already present" error: return — the goal is already achieved.
 * 4. On `ConflictError` (concurrent write moved the hash): retry from step 1,
 *    up to `maxAttempts` total.
 * 5. Any other error propagates.
 *
 * @param client         A `StarfishClient` instance.
 * @param collectionPath Bare collection path (e.g. `"spaces/sp-123"`).
 * @param recipient      Recipient to add (at minimum `{ subKem: "<kemPubHex>" }`).
 * @param adder          The adder's keypair. Must already be in the keyring epoch
 *                       (unless this is the initial creation — see `opts.adderKemPub`).
 * @param opts           Optional overrides (keyringPath, adderKemPub, maxAttempts, recipientOpts).
 *
 * @returns `"added"` if the recipient was newly added, `"already-present"` if they
 *          were already in the keyring (idempotent success).
 */
export async function ensureKeyringRecipient(
  client: StarfishClient,
  collectionPath: string,
  recipient: RecipientRef,
  adder: AdderKeys,
  opts: EnsureKeyringRecipientOptions = {},
): Promise<"added" | "already-present"> {
  const keyringPath = opts.keyringPath ?? keyringPathFor(collectionPath)
  const maxAttempts = Math.max(1, opts.maxAttempts ?? 3)

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Step 1: Ensure the keyring document exists.
    // Try to pull the keyring; if 404 and adderKemPub is provided, create it.
    let exists = true
    try {
      await client.pull(`/pull/${keyringPath}`)
    } catch (pullErr: unknown) {
      if (getStatus(pullErr) === 404) {
        exists = false
      } else {
        throw pullErr
      }
    }

    if (!exists) {
      if (!opts.adderKemPub) {
        // No creation possible — fall through to addCollectionRecipient which
        // will throw the "no keyring exists" error with a helpful message.
      } else {
        // Create the keyring with the adder as the first epoch recipient.
        try {
          const { keyring } = await createKeyring(
            { edPrivHex: adder.edPriv, edPubHex: adder.edPub },
            [{ subKemHex: opts.adderKemPub }],
          )
          await client.push(
            `/push/${keyringPath}`,
            keyring as unknown as Record<string, unknown>,
            null,
          )
        } catch (createErr: unknown) {
          if (createErr instanceof ConflictError) {
            // A concurrent writer also created it — retry from the top.
            continue
          }
          throw createErr
        }
      }
    }

    // Step 2: Add the recipient.
    try {
      await addCollectionRecipient(client, collectionPath, recipient, adder, opts.recipientOpts)
      return "added"
    } catch (addErr: unknown) {
      if (isAlreadyPresent(addErr)) return "already-present"
      if (addErr instanceof ConflictError && attempt < maxAttempts - 1) continue
      throw addErr
    }
  }

  throw new ConflictError()
}

/** Re-exported for convenience — compute the keyring document path for a collection. */
export { keyringPathFor }
