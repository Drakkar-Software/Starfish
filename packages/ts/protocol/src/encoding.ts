/**
 * URL-safe Base64 and link-fragment utilities.
 *
 * Two small helpers that every starfish consumer needs when building shareable
 * invite/identity links that ride in a URL fragment (`#`):
 *
 * - {@link toBase64Url} / {@link fromBase64Url} — UTF-8 string ↔ base64url
 *   (no padding, `+/` → `-_`). Works on web, Node.js, and React Native/Hermes.
 * - {@link encodeLinkFragment} / {@link decodeLinkFragment} — pack/unpack a
 *   JSON token into a URL fragment with the origin stripped from the path.
 *
 * These functions are deliberately pure (no I/O, no starfish protocol
 * knowledge) so they can be called during link generation / QR code
 * rendering without any SDK initialisation.
 */

// ── base64url ─────────────────────────────────────────────────────────────────

/**
 * Encode a UTF-8 string to base64url (URL-safe base64, no `=` padding).
 *
 * Uses `btoa` when available (browser / Node ≥ 16) and `Buffer.from` as a
 * Node-specific fallback so the function works in all environments without
 * injecting a platform provider.
 */
export function toBase64Url(json: string): string {
  const bytes = new TextEncoder().encode(json)
  // Build a binary string one byte at a time — no spread, so there is no
  // argument-count ceiling on large payloads.
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  const b64 =
    typeof btoa === "function"
      ? btoa(bin)
      : (globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } })
          .Buffer!.from(json, "utf-8")
          .toString("base64")
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/**
 * Decode a base64url string back to a UTF-8 string.
 *
 * Tolerant of missing `=` padding and either `+/` or `-_` alphabet.
 */
export function fromBase64Url(b64url: string): string {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/")
  if (typeof atob === "function") {
    const bin = atob(b64)
    const bytes = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
    return new TextDecoder().decode(bytes)
  }
  return (
    globalThis as { Buffer?: { from(s: string, enc: string): { toString(enc: string): string } } }
  ).Buffer!.from(b64, "base64").toString("utf-8")
}

// ── link-fragment ─────────────────────────────────────────────────────────────

/**
 * Pack `token` into a shareable URL with the origin stripped from `path`.
 *
 * The canonical wire form (see `tests/test-vectors/base64url.json`) is
 * `base64url(JSON.stringify([origin, path, token]))`, byte-identical to the
 * Python `encode_link_fragment`, so a link minted by either language decodes on
 * the other:
 *
 * ```
 * https://app.example.com/join#WyJodHRwczovL2FwcC5leGFtcGxlLmNvbSIsIi9qb2luIix7Li4ufV0
 * ```
 *
 * The origin is prepended so the result is a fully-qualified link; the caller
 * can pass their own `window.location.origin`.
 *
 * @param origin   e.g. `"https://app.example.com"` — trailing slashes stripped.
 * @param path     e.g. `"/join"` or `"join"`.
 * @param token    Any JSON-serialisable value to encode in the fragment.
 */
export function encodeLinkFragment(origin: string, path: string, token: unknown): string {
  const base = origin.replace(/\/+$/, "")
  const p = path.replace(/^\/+/, "")
  return `${base}/${p}#${toBase64Url(JSON.stringify([origin, path, token]))}`
}

/**
 * Decode a link fragment previously produced by {@link encodeLinkFragment}.
 *
 * @param fragment  The raw fragment string: either the full `#…` hash (the `#`
 *                  is stripped automatically) or just the base64url payload.
 * @param validate  Type-guard / transformer that returns the typed token or
 *                  throws/returns `null` on a shape mismatch.
 * @param errMsg    Message thrown when parsing or validation fails.
 *
 * @throws {Error} when the fragment is malformed or fails `validate`.
 */
export function decodeLinkFragment<T>(
  fragment: string,
  validate: (tok: unknown) => T | null,
  errMsg = "invalid link token",
): T {
  const raw = fragment.startsWith("#") ? fragment.slice(1) : fragment
  let parsed: unknown
  try {
    parsed = JSON.parse(fromBase64Url(raw))
  } catch {
    throw new Error(errMsg)
  }
  // Canonical form is [origin, path, token]; recover the token before validating.
  // A bare (non-array) payload is tolerated for resilience against older
  // single-value fragments.
  const token = Array.isArray(parsed) && parsed.length >= 3 ? parsed[2] : parsed
  const result = validate(token)
  if (result === null || result === undefined) throw new Error(errMsg)
  return result
}
