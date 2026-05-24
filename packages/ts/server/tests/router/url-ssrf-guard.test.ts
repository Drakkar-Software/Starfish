import { describe, it, expect } from "vitest"
import { validateUrlNotPrivate } from "../../src/router/helpers.js"

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
  ]
  for (const url of blocked) {
    it(`blocks private/loopback target ${url}`, () => {
      expect(validateUrlNotPrivate(url)).toBe(false)
    })
  }

  for (const url of ["http://example.com/", "http://8.8.8.8/"]) {
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
