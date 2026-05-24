import type { StarfishClient } from "@drakkar.software/starfish-client"
import { StarfishHttpError } from "@drakkar.software/starfish-client"

export interface PullEntitlementsOptions {
  /**
   * Path template for the entitlement document.
   * `{userId}` is replaced with the `userId` argument.
   * Defaults to `"/pull/users/{userId}/entitlements"`.
   */
  path?: string
  /**
   * Field name in the document `data` object that holds the feature slug array.
   * Defaults to `"features"`.
   */
  field?: string
}

/**
 * Fetches the list of feature slugs from a user's entitlement document.
 *
 * Returns an empty array if the document does not exist yet or the features
 * field is absent — so callers never need to handle a 404.
 *
 * ```ts
 * import { pullEntitlements } from "@drakkar.software/starfish-client"
 *
 * const features = await pullEntitlements(client, userId)
 * // e.g. ["premium-package-1", "paid-cloud-sync"]
 *
 * if (features.includes("paid-cloud-sync")) {
 *   // unlock cloud sync UI
 * }
 * ```
 *
 * The path template must match the server-side collection's `storagePath`.
 * With the recommended default config:
 * ```ts
 * { storagePath: "users/{identity}/entitlements" }
 * // → path: "/pull/users/{userId}/entitlements"  (default)
 * ```
 */
export async function pullEntitlements(
  client: StarfishClient,
  userId: string,
  opts?: PullEntitlementsOptions,
): Promise<string[]> {
  const path = (opts?.path ?? "/pull/users/{userId}/entitlements").replace("{userId}", userId)
  const field = opts?.field ?? "features"

  try {
    const result = await client.pull(path)
    const list = (result.data as Record<string, unknown> | null)?.[field]
    if (!Array.isArray(list)) return []
    return list.filter((s): s is string => typeof s === "string")
  } catch (err) {
    if (err instanceof StarfishHttpError && err.status === 404) return []
    throw err
  }
}
