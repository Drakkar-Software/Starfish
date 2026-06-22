/**
 * CSPRNG-backed identifier helpers.
 *
 * {@link randomId} — a 128-bit (16-byte) hex id suitable as a document key,
 * collection id, or any storage path segment. Uses `crypto.getRandomValues`
 * (Web Crypto), available in all supported environments (browser, Node ≥ 15,
 * React Native / Hermes with `react-native-quick-crypto`).
 *
 * {@link slugify} — converts an arbitrary display name into a URL/path-safe
 * `[a-z0-9-]` slug. Useful for the human-readable component of a compound id
 * such as `<objectId>-<slug>-<ts>`. The slug is capped at 40 characters.
 */

/**
 * Generate a CSPRNG-backed 128-bit hex id (32 hex chars).
 *
 * Use this for every document key, collection id, blob id, or any other id
 * that must be unguessable. Hex output is path-safe and compatible with both
 * URL path segments and server-side storage keys.
 *
 * @example
 * ```ts
 * const spaceId = randomId()  // "a3f21b8c0e4d9167…"
 * ```
 */
export function randomId(): string {
  const bytes = new Uint8Array(16)
  globalThis.crypto.getRandomValues(bytes)
  let s = ""
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0")
  return s
}

/**
 * Convert a display name to a URL/path-safe slug.
 *
 * Rules:
 * - Lowercased.
 * - Any run of non-`[a-z0-9]` characters is collapsed to a single `-`.
 * - Leading/trailing `-` stripped.
 * - Capped at 40 characters.
 * - Falls back to `fallback` (default `"item"`) when the name strips to empty.
 *
 * @example
 * ```ts
 * slugify("Hello World!")  // "hello-world"
 * slugify("  ")            // "item"
 * slugify("My Café", "doc") // "my-caf"
 * ```
 */
export function slugify(name: string, fallback = "item"): string {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40) || fallback
  )
}
