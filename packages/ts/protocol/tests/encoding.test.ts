/**
 * Tests for toBase64Url / fromBase64Url and the link-fragment helpers.
 */
import { describe, it, expect } from "vitest"
import {
  toBase64Url,
  fromBase64Url,
  encodeLinkFragment,
  decodeLinkFragment,
} from "../src/encoding.js"

describe("toBase64Url / fromBase64Url", () => {
  it("round-trips a plain ASCII string", () => {
    const original = "hello world"
    expect(fromBase64Url(toBase64Url(original))).toBe(original)
  })

  it("round-trips a JSON payload", () => {
    const original = JSON.stringify({ type: "space", id: "abc123", ts: 1_234_567 })
    expect(fromBase64Url(toBase64Url(original))).toBe(original)
  })

  it("round-trips a string with multi-byte Unicode characters", () => {
    const original = "héllo wörld 🌍"
    expect(fromBase64Url(toBase64Url(original))).toBe(original)
  })

  it("produces URL-safe output (no +, /, or =)", () => {
    // Generate payloads that produce all three problematic base64 chars.
    for (let i = 0; i < 256; i++) {
      const encoded = toBase64Url(String.fromCharCode(i) + "xy")
      expect(encoded).not.toMatch(/[+/=]/)
    }
  })

  it("decodes strings with either + / or - _ alphabet", () => {
    // Manually produce a regular base64 string and check both decode.
    const json = '{"x":1}'
    const regularB64 = btoa(json)
    const urlSafe = regularB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    expect(fromBase64Url(regularB64)).toBe(json)
    expect(fromBase64Url(urlSafe)).toBe(json)
  })

  it("round-trips an empty string", () => {
    expect(fromBase64Url(toBase64Url(""))).toBe("")
  })

  // Cross-language test vector — byte-identical with Python's
  // base64.urlsafe_b64encode(json.encode()).rstrip(b"=")
  it("matches the cross-language test vector", () => {
    const payload = '{"type":"space","id":"abc"}'
    const expected = "eyJ0eXBlIjoic3BhY2UiLCJpZCI6ImFiYyJ9"
    expect(toBase64Url(payload)).toBe(expected)
    expect(fromBase64Url(expected)).toBe(payload)
  })
})

interface SpaceToken {
  type: "space"
  id: string
}

function isSpaceToken(v: unknown): SpaceToken | null {
  if (typeof v !== "object" || v === null) return null
  const o = v as Record<string, unknown>
  if (o.type !== "space" || typeof o.id !== "string") return null
  return { type: "space", id: o.id }
}

describe("encodeLinkFragment / decodeLinkFragment", () => {
  const ORIGIN = "https://app.example.com"
  const PATH = "/join/space"
  const TOKEN: SpaceToken = { type: "space", id: "sp-123" }

  it("encodes a token into a fully-qualified URL with a hash fragment", () => {
    const url = encodeLinkFragment(ORIGIN, PATH, TOKEN)
    expect(url.startsWith(`${ORIGIN}/join/space#`)).toBe(true)
    expect(url).not.toContain("=")
  })

  it("decodes the fragment back to the original token", () => {
    const url = encodeLinkFragment(ORIGIN, PATH, TOKEN)
    const fragment = url.split("#")[1]!
    expect(decodeLinkFragment(fragment, isSpaceToken)).toEqual(TOKEN)
  })

  it("decodes a fragment that starts with #", () => {
    const url = encodeLinkFragment(ORIGIN, PATH, TOKEN)
    const fragment = "#" + url.split("#")[1]!
    expect(decodeLinkFragment(fragment, isSpaceToken)).toEqual(TOKEN)
  })

  it("strips trailing slashes from the origin in the URL prefix", () => {
    const url = encodeLinkFragment(ORIGIN + "///", PATH, TOKEN)
    expect(url.startsWith(`${ORIGIN}/join/space#`)).toBe(true)
    // Token still round-trips regardless of how the origin was spelled.
    expect(decodeLinkFragment(url.split("#")[1]!, isSpaceToken)).toEqual(TOKEN)
  })

  it("normalizes a leading slash on the path in the URL prefix", () => {
    expect(encodeLinkFragment(ORIGIN, "/join", TOKEN).startsWith(`${ORIGIN}/join#`)).toBe(true)
    expect(encodeLinkFragment(ORIGIN, "join", TOKEN).startsWith(`${ORIGIN}/join#`)).toBe(true)
  })

  it("emits the canonical [origin, path, token] array form (cross-language parity)", () => {
    // The fragment is base64url(JSON([origin, path, token])), byte-identical to
    // Python; decode recovers the token. Before this, TS encoded the bare token
    // and Python encoded the array, so links were mutually undecodable.
    const url = encodeLinkFragment(ORIGIN, PATH, TOKEN)
    const fragment = url.split("#")[1]!
    expect(JSON.parse(fromBase64Url(fragment))).toEqual([ORIGIN, PATH, TOKEN])
  })

  it("matches the cross-language link-fragment test vector", () => {
    const origin = "https://app.example.com"
    const path = "/spaces/sp-abc"
    const token = { type: "space-invite", id: "sp-abc", expiresAt: 1900000000 }
    const expectedFragment =
      "WyJodHRwczovL2FwcC5leGFtcGxlLmNvbSIsIi9zcGFjZXMvc3AtYWJjIix7InR5cGUiOiJzcGFjZS1pbnZpdGUiLCJpZCI6InNwLWFiYyIsImV4cGlyZXNBdCI6MTkwMDAwMDAwMH1d"
    const url = encodeLinkFragment(origin, path, token)
    const fragment = url.split("#")[1]!
    expect(fragment).toBe(expectedFragment)
    // And it decodes on this side.
    expect(decodeLinkFragment(fragment, (t) => t as typeof token)).toEqual(token)
  })

  it("throws with the given errMsg on a malformed fragment", () => {
    expect(() => decodeLinkFragment("not-valid-base64!!!!", isSpaceToken, "bad link")).toThrow("bad link")
  })

  it("throws when validation fails", () => {
    // Encode a token (via the canonical array form) that doesn't match SpaceToken.
    const badFrag = encodeLinkFragment(ORIGIN, PATH, { type: "node" }).split("#")[1]!
    expect(() => decodeLinkFragment(badFrag, isSpaceToken, "bad link")).toThrow("bad link")
  })
})
