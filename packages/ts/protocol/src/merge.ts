import { UNSAFE_KEYS } from "./unsafe-keys.js"

export function deepMerge(
  local: Record<string, unknown>,
  remote: Record<string, unknown>
): Record<string, unknown> {
  // Filter unsafe keys out of BOTH sides — not just `remote` — so an unsafe
  // key already present in `local` cannot survive the merge (matches the
  // Python implementation).
  const merged: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(local)) {
    if (!UNSAFE_KEYS.has(key)) merged[key] = value
  }
  for (const key of Object.keys(remote)) {
    // Prototype-pollution guard. JSON.parse leaves `__proto__`, `constructor`,
    // and `prototype` as own keys; if we copy them into a plain object and a
    // downstream consumer later does `obj.someKey` access, the lookup will
    // traverse the polluted prototype chain. Drop them up-front so the
    // merged result is safe regardless of how it's consumed.
    if (UNSAFE_KEYS.has(key)) continue
    const remoteVal = remote[key]
    const localVal = merged[key]
    if (
      remoteVal !== null &&
      typeof remoteVal === "object" &&
      !Array.isArray(remoteVal) &&
      localVal !== null &&
      typeof localVal === "object" &&
      !Array.isArray(localVal)
    ) {
      merged[key] = deepMerge(
        localVal as Record<string, unknown>,
        remoteVal as Record<string, unknown>
      )
    } else {
      merged[key] = remoteVal
    }
  }
  return merged
}
