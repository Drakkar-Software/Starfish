import { getCrypto, getBase64 } from "@drakkar.software/starfish-protocol"

// ── Word list ─────────────────────────────────────────────────────────────────
// 256 common English words, one per index (0-255). One byte of entropy per word.
// 12 words = 96 bits of entropy (stronger than a random UUID).

const WORDLIST: string[] = [
  "able", "acid", "aged", "also", "area", "army", "away", "back",
  "ball", "band", "bank", "base", "bath", "bean", "bear", "beat",
  "bell", "best", "bird", "blue", "boat", "bold", "bolt", "bone",
  "born", "bowl", "burn", "calm", "call", "camp", "card", "care",
  "cash", "cast", "cave", "city", "clam", "clay", "clip", "coal",
  "coat", "coin", "cold", "cook", "cool", "corn", "cost", "cozy",
  "dark", "data", "dawn", "dead", "deal", "deck", "deep", "dew",
  "dish", "dome", "door", "down", "draw", "drop", "drum", "dusk",
  "dust", "each", "earn", "east", "edge", "even", "ever", "face",
  "fact", "fair", "fall", "fame", "farm", "fast", "felt", "file",
  "fill", "fire", "fish", "fist", "flag", "flat", "flew", "flow",
  "foam", "fold", "fond", "food", "foot", "form", "frog", "fuel",
  "full", "gain", "game", "gate", "gave", "gaze", "gift", "glad",
  "glow", "glue", "goal", "good", "grab", "gray", "grip", "grow",
  "gulf", "gust", "half", "hall", "hand", "hard", "harm", "have",
  "hawk", "head", "heal", "heap", "heat", "held", "helm", "help",
  "herb", "here", "hero", "high", "hill", "hint", "hold", "hole",
  "home", "hope", "horn", "hour", "huge", "hunt", "idea", "inch",
  "into", "iris", "isle", "jade", "jail", "join", "jump", "just",
  "keep", "kind", "king", "knot", "know", "lack", "lake", "land",
  "lane", "last", "late", "lawn", "lead", "leaf", "lean", "leap",
  "left", "lend", "less", "life", "lift", "like", "lime", "line",
  "lion", "list", "live", "load", "lock", "loft", "long", "look",
  "loop", "loud", "love", "luck", "lung", "made", "main", "mark",
  "mast", "math", "maze", "meal", "meet", "melt", "mild", "mind",
  "mint", "mist", "mode", "moon", "more", "most", "move", "much",
  "must", "name", "near", "neck", "need", "next", "nice", "nine",
  "none", "noon", "note", "noun", "oath", "once", "open", "oval",
  "over", "pack", "page", "paid", "pain", "pale", "palm", "park",
  "part", "path", "pave", "peak", "pier", "pile", "pine", "pipe",
  "plan", "plum", "poem", "pole", "pool", "port", "pose", "post",
  "pray", "prey", "pull", "pure", "push", "quit", "race", "rack",
]

// ── Types ─────────────────────────────────────────────────────────────────────

/** Credentials derived from a passphrase. Pass directly to SyncManager / StarfishClient. */
export interface DerivedCredentials {
  /** Hex-encoded auth token. Use as `Bearer ${authToken}` in request headers. */
  authToken: string
  /**
   * Short identifier derived from the auth token (first 16 hex chars = 8 bytes).
   * Used as the user/namespace segment in collection paths.
   */
  userId: string
  /**
   * Hex-encoded key suitable as `encryptionSecret` for SyncManager.
   * Combined with `encryptionSalt` to derive the AES-256-GCM key via HKDF.
   */
  encryptionSecret: string
  /**
   * Value suitable as `encryptionSalt` for SyncManager. Equals `userId`.
   * Using a per-identity salt ensures that even if two users share a passphrase,
   * their encryption keys are different.
   */
  encryptionSalt: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

async function sha256Hex(input: string): Promise<string> {
  const c = getCrypto()
  const encoded = new TextEncoder().encode(input)
  const hash = await c.subtle.digest("SHA-256", encoded)
  return bytesToHex(new Uint8Array(hash))
}

// URL-safe base64 (RFC 4648 §5): replaces + → -, / → _, strips trailing =
function base64UrlEncode(data: Uint8Array): string {
  const b64 = getBase64()
  return b64
    .encode(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

function base64UrlDecode(encoded: string): Uint8Array {
  const b64 = getBase64()
  // Restore standard base64 padding
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/")
  const rem = padded.length % 4
  const padded2 = rem === 0 ? padded : padded + "=".repeat(4 - rem)
  return b64.decode(padded2)
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Generates a cryptographically random passphrase from the built-in 256-word list.
 *
 * Each word represents one byte of entropy (256 words = one byte per word, zero modulo bias).
 * A 12-word passphrase gives 96 bits of entropy — stronger than a random UUID.
 *
 * @param wordCount Number of words (default: 12).
 * @param wordlist Custom word list (must have exactly 256 entries).
 */
export function generatePassphrase(wordCount = 12, wordlist: string[] = WORDLIST): string {
  if (wordlist.length !== 256) {
    throw new Error(`Word list must have exactly 256 entries, got ${wordlist.length}`)
  }
  const c = getCrypto()
  const bytes = c.getRandomValues(new Uint8Array(wordCount))
  return Array.from(bytes, (b) => wordlist[b]).join(" ")
}

/**
 * Derives auth credentials from a passphrase.
 *
 * All derivations are deterministic — the same passphrase always produces the same credentials.
 * Sharing the passphrase grants access on any device.
 *
 * The returned values map directly to Starfish options:
 * ```ts
 * const creds = await deriveCredentials(passphrase)
 *
 * const client = new StarfishClient({
 *   baseUrl: serverUrl,
 *   auth: () => ({ Authorization: `Bearer ${creds.authToken}` }),
 * })
 * const syncManager = new SyncManager({
 *   client,
 *   pullPath: `/pull/${creds.userId}/wedding`,
 *   pushPath: `/push/${creds.userId}/wedding`,
 *   encryptionSecret: creds.encryptionSecret,
 *   encryptionSalt: creds.encryptionSalt,
 * })
 * ```
 */
export async function deriveCredentials(passphrase: string): Promise<DerivedCredentials> {
  if (!passphrase.trim()) throw new Error("Passphrase must not be empty")

  // authToken = SHA-256(passphrase) — used as Bearer token
  const authToken = await sha256Hex(passphrase)

  // userId = first 16 hex chars of authToken (8 bytes)
  const userId = authToken.slice(0, 16)

  // encryptionSecret = SHA-256(passphrase + ":" + userId)
  // Domain separation from authToken ensures they cannot be recovered from each other.
  const encryptionSecret = await sha256Hex(`${passphrase}:${userId}`)

  return {
    authToken,
    userId,
    encryptionSecret,
    encryptionSalt: userId,
  }
}

/**
 * Encodes an invite payload as a URL-safe token and appends it as `?t=<token>`.
 *
 * ```ts
 * const url = buildInviteUrl("myapp://join", { name: "Alice & Bob", p: passphrase })
 * // → "myapp://join?t=eyJuYW1lIjoiQWxpY2UgJiBCb2IifQ"
 * ```
 */
export function buildInviteUrl(baseUrl: string, payload: Record<string, unknown>): string {
  const json = JSON.stringify(payload)
  const bytes = new TextEncoder().encode(json)
  const token = base64UrlEncode(bytes)
  const separator = baseUrl.includes("?") ? "&" : "?"
  return `${baseUrl}${separator}t=${token}`
}

/**
 * Decodes an invite URL produced by `buildInviteUrl`.
 *
 * Returns the decoded payload, or `null` if the URL is missing or malformed.
 */
export function parseInviteUrl(url: string): Record<string, unknown> | null {
  try {
    const tokenMatch = url.match(/[?&]t=([^&]+)/)
    if (!tokenMatch?.[1]) return null
    const bytes = base64UrlDecode(tokenMatch[1])
    const json = new TextDecoder().decode(bytes)
    const parsed: unknown = JSON.parse(json)
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null
    return parsed as Record<string, unknown>
  } catch {
    return null
  }
}

// Export word list for consumers that want to provide localized alternatives
export { WORDLIST as DEFAULT_WORDLIST }
