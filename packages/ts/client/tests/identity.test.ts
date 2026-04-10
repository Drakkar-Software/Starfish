import { describe, it, expect, beforeAll } from "vitest"
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import {
  generatePassphrase,
  deriveCredentials,
  buildInviteUrl,
  parseInviteUrl,
  DEFAULT_WORDLIST,
} from "../src/identity.js"

// jsdom provides globalThis.crypto — no configurePlatform needed in browser-like test env.
// But we need a base64 provider for non-browser environments.
beforeAll(() => {
  if (typeof globalThis.btoa !== "function") {
    // Node.js < 16 fallback (unlikely in test env but safe)
    configurePlatform({
      base64: {
        encode: (data) => Buffer.from(data).toString("base64"),
        decode: (str) => new Uint8Array(Buffer.from(str, "base64")),
      },
    })
  }
})

// ── generatePassphrase ────────────────────────────────────────────────────────

describe("generatePassphrase", () => {
  it("returns a string with the correct number of words", () => {
    const phrase = generatePassphrase()
    const words = phrase.split(" ")
    expect(words).toHaveLength(12)
  })

  it("all words come from the default word list", () => {
    const phrase = generatePassphrase()
    for (const word of phrase.split(" ")) {
      expect(DEFAULT_WORDLIST).toContain(word)
    }
  })

  it("respects a custom wordCount", () => {
    expect(generatePassphrase(6).split(" ")).toHaveLength(6)
    expect(generatePassphrase(24).split(" ")).toHaveLength(24)
  })

  it("generates different passphrases on each call", () => {
    const phrases = new Set(Array.from({ length: 10 }, () => generatePassphrase()))
    // With 96 bits of entropy, collisions are astronomically unlikely
    expect(phrases.size).toBe(10)
  })

  it("throws when the word list does not have 256 entries", () => {
    expect(() => generatePassphrase(12, ["only", "two"])).toThrow("Word list must have exactly 256")
  })

  it("default word list has exactly 256 entries", () => {
    expect(DEFAULT_WORDLIST).toHaveLength(256)
  })

  it("default word list has no duplicates", () => {
    const unique = new Set(DEFAULT_WORDLIST)
    expect(unique.size).toBe(256)
  })
})

// ── deriveCredentials ─────────────────────────────────────────────────────────

describe("deriveCredentials", () => {
  it("returns all expected fields", async () => {
    const creds = await deriveCredentials("able acid aged")
    expect(creds).toHaveProperty("authToken")
    expect(creds).toHaveProperty("userId")
    expect(creds).toHaveProperty("encryptionSecret")
    expect(creds).toHaveProperty("encryptionSalt")
  })

  it("authToken is a 64-char hex string (SHA-256)", async () => {
    const creds = await deriveCredentials("able acid aged")
    expect(creds.authToken).toMatch(/^[0-9a-f]{64}$/)
  })

  it("userId is the first 16 chars of authToken", async () => {
    const creds = await deriveCredentials("able acid aged")
    expect(creds.userId).toBe(creds.authToken.slice(0, 16))
  })

  it("encryptionSalt equals userId", async () => {
    const creds = await deriveCredentials("able acid aged")
    expect(creds.encryptionSalt).toBe(creds.userId)
  })

  it("encryptionSecret is a 64-char hex string distinct from authToken", async () => {
    const creds = await deriveCredentials("able acid aged")
    expect(creds.encryptionSecret).toMatch(/^[0-9a-f]{64}$/)
    expect(creds.encryptionSecret).not.toBe(creds.authToken)
  })

  it("is deterministic — same passphrase always yields same credentials", async () => {
    const a = await deriveCredentials("pond river lake")
    const b = await deriveCredentials("pond river lake")
    expect(a).toEqual(b)
  })

  it("different passphrases yield different credentials", async () => {
    const a = await deriveCredentials("able acid aged")
    const b = await deriveCredentials("able acid area")
    expect(a.authToken).not.toBe(b.authToken)
    expect(a.encryptionSecret).not.toBe(b.encryptionSecret)
    expect(a.userId).not.toBe(b.userId)
  })

  it("throws on empty passphrase", async () => {
    await expect(deriveCredentials("")).rejects.toThrow("empty")
    await expect(deriveCredentials("   ")).rejects.toThrow("empty")
  })
})

// ── buildInviteUrl / parseInviteUrl ───────────────────────────────────────────

describe("buildInviteUrl", () => {
  it("appends ?t= to a base URL", () => {
    const url = buildInviteUrl("myapp://join", { n: "Alice", p: "secret" })
    expect(url).toMatch(/^myapp:\/\/join\?t=/)
  })

  it("appends &t= when base URL already has query params", () => {
    const url = buildInviteUrl("https://example.com/join?ref=email", { n: "Bob" })
    expect(url).toMatch(/&t=/)
  })

  it("uses URL-safe base64 (no + / or =)", () => {
    const url = buildInviteUrl("myapp://join", { n: "test" })
    const token = url.split("?t=")[1]
    expect(token).not.toMatch(/[+/=]/)
  })
})

describe("parseInviteUrl", () => {
  it("round-trips through buildInviteUrl", () => {
    const payload = { n: "Alice & Bob", p: "my secret passphrase" }
    const url = buildInviteUrl("myapp://join", payload)
    const decoded = parseInviteUrl(url)
    expect(decoded).toEqual(payload)
  })

  it("handles nested and unicode payloads", () => {
    const payload = { name: "Álice & Böb 🎉", nested: { count: 42 } }
    const url = buildInviteUrl("https://example.com", payload)
    expect(parseInviteUrl(url)).toEqual(payload)
  })

  it("returns null for URLs without ?t= param", () => {
    expect(parseInviteUrl("myapp://join")).toBeNull()
    expect(parseInviteUrl("https://example.com?other=value")).toBeNull()
  })

  it("returns null for malformed tokens", () => {
    expect(parseInviteUrl("myapp://join?t=!!!invalid!!!")).toBeNull()
    expect(parseInviteUrl("myapp://join?t=bm90anNvbg")).toBeNull() // "notjson" in base64
  })

  it("returns null for tokens that decode to non-objects", () => {
    // base64url of "[1,2,3]" (an array, not an object)
    const arrayToken = buildInviteUrl("x://y", [1, 2, 3] as unknown as Record<string, unknown>)
    // arrays stringify to plain JSON, but parseInviteUrl should reject them
    const url = arrayToken.replace(/\?t=.*/, `?t=${btoa("[1,2,3]").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")}`)
    expect(parseInviteUrl(url)).toBeNull()
  })
})
