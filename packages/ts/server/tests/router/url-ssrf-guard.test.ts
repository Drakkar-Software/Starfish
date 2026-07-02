import { describe, it, expect } from "vitest"
import { validateUrlNotPrivate, validateUrlNotPrivateAsync } from "../../src/router/helpers.js"

// Cross-language parity probe for the public SSRF guard. See the Python twin
// test_url_ssrf_guard.py for the full divergence write-up. Summary: TypeScript
// uses WHATWG `new URL`, which normalises alternate IPv4 notations
// (2130706433 / 0x7f000001 / 0177.0.0.1 / 127.1) to "127.0.0.1" — so TS blocks
// those, where Python's ipaddress-based guard lets them through. The reverse
// hole (IPv4-mapped IPv6 loopback) is the it.fails pin below.
describe("validateUrlNotPrivate", () => {
  const blocked = [
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://localhost/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/",
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://0.0.0.0/",
    // `new URL` normalises these alternate spellings of 127.0.0.1 → blocked.
    "http://2130706433/",
    "http://0x7f000001/",
    "http://0177.0.0.1/",
    "http://127.1/",
    // Reserved / special-use ranges Python's `ipaddress` also blocks — the TS
    // classifier now blocks the identical set, plus CGNAT (100.64.0.0/10) which
    // neither language caught before.
    "http://100.64.0.1/",       // 100.64.0.0/10 CGNAT (RFC 6598)
    "http://100.127.255.255/",  // top of CGNAT
    "http://192.0.2.1/",        // 192.0.2.0/24 TEST-NET-1
    "http://198.18.0.1/",       // 198.18.0.0/15 benchmarking
    "http://198.19.255.255/",   // top of 198.18.0.0/15
    "http://198.51.100.5/",     // 198.51.100.0/24 TEST-NET-2
    "http://203.0.113.5/",      // 203.0.113.0/24 TEST-NET-3
    "http://192.0.0.1/",        // 192.0.0.0/24 IETF protocol assignments
    "http://240.0.0.1/",        // 240.0.0.0/4 reserved
    "http://255.255.255.255/",  // limited broadcast (within 240.0.0.0/4)
  ]
  for (const url of blocked) {
    it(`blocks private/loopback target ${url}`, () => {
      expect(validateUrlNotPrivate(url)).toBe(false)
    })
  }

  // Addresses just OUTSIDE the newly-blocked ranges must stay public (no over-blocking).
  for (const url of ["http://example.com/", "http://8.8.8.8/", "http://100.63.255.255/", "http://100.128.0.1/", "http://199.0.0.1/", "http://239.255.255.255/"]) {
    it(`allows public target ${url}`, () => {
      expect(validateUrlNotPrivate(url)).toBe(true)
    })
  }

  // `new URL("http://[::ffff:127.0.0.1]/").hostname` compresses to
  // "[::ffff:7f00:1]" (hex), which the dotted-quad v4-mapped regex missed. Fixed:
  // a hex IPv4-mapped branch now decodes the embedded IPv4 and blocks it — Python's
  // ipaddress flags ::ffff:127.0.0.1 as private and blocks it too.
  it("blocks IPv4-mapped IPv6 loopback (both dotted-quad and compressed hex form)", () => {
    expect(validateUrlNotPrivate("http://[::ffff:127.0.0.1]/")).toBe(false)
    expect(validateUrlNotPrivate("http://[::ffff:7f00:1]/")).toBe(false)
  })
})

// The string-only guard cannot see that a public-looking HOSTNAME resolves to an
// internal address (DNS-based SSRF). validateUrlNotPrivateAsync resolves the name
// and rejects if ANY resolved address is private. A resolver is injected so these
// tests are deterministic and never touch the network.
describe("validateUrlNotPrivateAsync", () => {
  it("rejects a literal private host without resolving (fast pre-filter)", async () => {
    let called = false
    const resolver = async () => {
      called = true
      return ["8.8.8.8"]
    }
    expect(await validateUrlNotPrivateAsync("http://127.0.0.1/", resolver)).toBe(false)
    expect(called).toBe(false) // short-circuited by the synchronous check
  })

  it("rejects a public-looking hostname that resolves to a private/loopback address", async () => {
    expect(await validateUrlNotPrivateAsync("http://internal.example.com/", async () => ["10.0.0.5"])).toBe(false)
    expect(await validateUrlNotPrivateAsync("http://rebind.example.com/", async () => ["127.0.0.1"])).toBe(false)
    // Any single private address in the resolved set fails the whole check.
    expect(await validateUrlNotPrivateAsync("http://mixed.example.com/", async () => ["8.8.8.8", "192.168.1.1"])).toBe(false)
    // CGNAT resolution is rejected too (parity with the literal classifier).
    expect(await validateUrlNotPrivateAsync("http://cg.example.com/", async () => ["100.64.0.1"])).toBe(false)
  })

  it("allows a hostname that resolves only to public addresses", async () => {
    expect(await validateUrlNotPrivateAsync("http://ok.example.com/", async () => ["8.8.8.8", "1.1.1.1"])).toBe(true)
  })

  it("degrades to the string verdict when resolution yields nothing or fails", async () => {
    expect(await validateUrlNotPrivateAsync("http://ok.example.com/", async () => [])).toBe(true)
    expect(
      await validateUrlNotPrivateAsync("http://ok.example.com/", async () => {
        throw new Error("NXDOMAIN")
      }),
    ).toBe(true)
  })
})
