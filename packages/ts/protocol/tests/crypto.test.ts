import { describe, it, expect } from "vitest"
import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { deriveKey, deriveAesKeyBytes, IV_BYTES } from "../src/crypto.js"

const __dirname = dirname(fileURLToPath(import.meta.url))
const vectorPath = resolve(__dirname, "../../../../tests/test-vectors/crypto.json")
const vectors = JSON.parse(readFileSync(vectorPath, "utf-8")) as {
  secret: string
  salt: string
  info: string
  derived_key_hex: string
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
}

describe("deriveKey", () => {
  it("derives the exact key bytes anchored by the cross-language vector", async () => {
    const bytes = await deriveAesKeyBytes(vectors.secret, vectors.salt, vectors.info)
    expect(bytesToHex(bytes)).toBe(vectors.derived_key_hex)
  })

  it("derives a usable AES-256-GCM key from the shared vector inputs", async () => {
    const key = await deriveKey(vectors.secret, vectors.salt, vectors.info)
    const plaintext = JSON.stringify({ hello: "world", n: 42 })
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext))
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
    expect(new TextDecoder().decode(new Uint8Array(pt))).toBe(plaintext)
  })
})
