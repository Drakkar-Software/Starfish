/**
 * Object keys that must never be propagated through deep-merge / deep-clone
 * paths. Walking these into a plain object can pollute `Object.prototype`
 * (when assigned via dot syntax) or change the object's prototype chain
 * (when assigned via bracket syntax with `__proto__`).
 *
 * The set is exported from the protocol package so both the client-side
 * `deepMerge` and the server-side `deepSanitize` (in
 * `packages/ts/server/src/router/helpers.ts`) use exactly the same denylist.
 */
// `__proto__` / `constructor` / `prototype` are the JavaScript pollution
// vectors; `__class__` / `__dict__` are the Python equivalents. The full set is
// shared across both language implementations so a document merged in either
// ends up with an identical key set (and therefore an identical cross-language
// hash).
export const UNSAFE_KEYS: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__class__",
  "__dict__",
])

/**
 * Returns `true` if a key is one of the pollution-vector denylist entries.
 */
export function isUnsafeKey(key: string): boolean {
  return UNSAFE_KEYS.has(key)
}
