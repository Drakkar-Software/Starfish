import { getCrypto } from "./platform.js"

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
    const keys = Object.keys(obj).sort()
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
