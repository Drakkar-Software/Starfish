import { getCrypto } from "./platform.js"

/**
 * Compare two strings by Unicode code point, matching Python's `sorted()`.
 * JavaScript's default `Array.prototype.sort` orders by UTF-16 code unit, which
 * disagrees with code-point order whenever a BMP character ≥ U+E000 is compared
 * against a non-BMP character (encoded with a leading surrogate in U+D800–U+DBFF).
 * Object keys must sort identically in both languages or their canonical strings
 * — and therefore document hashes — diverge.
 */
function compareCodePoints(a: string, b: string): number {
  const ai = a[Symbol.iterator]()
  const bi = b[Symbol.iterator]()
  for (;;) {
    const x = ai.next()
    const y = bi.next()
    if (x.done && y.done) return 0
    if (x.done) return -1
    if (y.done) return 1
    const cx = x.value.codePointAt(0)!
    const cy = y.value.codePointAt(0)!
    if (cx !== cy) return cx - cy
  }
}

/**
 * Deterministic JSON serialization with sorted keys (recursive).
 * Must produce identical output to the server's stableStringify.
 */
export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return "null"
  if (typeof value === "boolean" || typeof value === "number") return JSON.stringify(value)
  if (typeof value === "string") return JSON.stringify(value)
  if (Array.isArray(value)) {
    return "[" + value.map(v => stableStringify(v)).join(",") + "]"
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>
    const keys = Object.keys(obj).sort(compareCodePoints)
    const pairs = keys.map(k => JSON.stringify(k) + ":" + stableStringify(obj[k]))
    return "{" + pairs.join(",") + "}"
  }
  return "null"
}

/**
 * Compute SHA-256 hex digest of the stable-stringified data.
 * Works in both browser (crypto.subtle) and Node.js environments.
 */
export async function computeHash(data: Record<string, unknown>): Promise<string> {
  const encoded = new TextEncoder().encode(stableStringify(data))
  const buf = await getCrypto().subtle.digest("SHA-256", encoded)
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
}
