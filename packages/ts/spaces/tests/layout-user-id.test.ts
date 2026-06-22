/**
 * Tests for `defaultUserIdFromEdPub` — the sha256[0:16 bytes] userId derivation.
 */
import { describe, it, expect } from "vitest"
import { defaultUserIdFromEdPub, USER_ID_HEX_LENGTH } from "../src/layout.js"

describe("defaultUserIdFromEdPub", () => {
  it("returns a hex string of length USER_ID_HEX_LENGTH (32 chars)", async () => {
    // Any 32-byte hex string works as an edPub for testing
    const edPub = "a".repeat(64)
    const userId = await defaultUserIdFromEdPub(edPub)
    expect(typeof userId).toBe("string")
    expect(userId.length).toBe(USER_ID_HEX_LENGTH) // 32 hex chars = 16 bytes
    expect(/^[0-9a-f]+$/.test(userId)).toBe(true)
  })

  it("is deterministic — same input → same output", async () => {
    const edPub = "deadbeef".repeat(8)
    const a = await defaultUserIdFromEdPub(edPub)
    const b = await defaultUserIdFromEdPub(edPub)
    expect(a).toBe(b)
  })

  it("different edPubs → different userIds", async () => {
    const a = await defaultUserIdFromEdPub("aa".repeat(32))
    const b = await defaultUserIdFromEdPub("bb".repeat(32))
    expect(a).not.toBe(b)
  })
})
