import { describe, it, expect } from "vitest"
import {
  CORS_ALLOW_HEADERS,
  HEADER_AUTHORIZATION,
  HEADER_CONTENT_TYPE,
  HEADER_SIG,
  HEADER_TS,
  HEADER_NONCE,
  HEADER_PUB,
} from "../src/constants.js"

describe("CORS_ALLOW_HEADERS", () => {
  it("contains exactly the seven expected entries in order", () => {
    expect([...CORS_ALLOW_HEADERS]).toEqual([
      "Authorization",
      "Content-Type",
      "X-Starfish-Sig",
      "X-Starfish-Ts",
      "X-Starfish-Nonce",
      "X-Starfish-Pub",
      "X-Requested-With",
    ])
  })

  it("is built from the HEADER_* constants (drift guard)", () => {
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_AUTHORIZATION)
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_CONTENT_TYPE)
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_SIG)
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_TS)
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_NONCE)
    expect(CORS_ALLOW_HEADERS).toContain(HEADER_PUB)
  })

  it("keeps every X-Starfish-* name aligned with its HEADER_* constant", () => {
    expect(HEADER_SIG).toBe("X-Starfish-Sig")
    expect(HEADER_TS).toBe("X-Starfish-Ts")
    expect(HEADER_NONCE).toBe("X-Starfish-Nonce")
    expect(HEADER_PUB).toBe("X-Starfish-Pub")
  })
})
