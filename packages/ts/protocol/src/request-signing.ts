/**
 * Per-request signing (v3.0).
 *
 * Each authenticated HTTP request carries a signature — under the crypto suite
 * named by `alg` (see `suites/`) — over a canonical encoding of
 * (alg, method, pathAndQuery, sha256(body), host, ts, nonce). The canonical
 * input is identical byte-for-byte across TypeScript and Python — see
 * `tests/test-vectors/request-signature.json` for locked cases.
 *
 * The `host` field binds a signature to one specific server host. Without
 * it, an Ed25519-signed request could be replayed against a different
 * Starfish server that shares no nonce cache with the original target.
 * The field is always present in the canonical input — it is the empty
 * string `""` when the caller omits `host` on `SignableRequest` — so an
 * attacker cannot bypass the bind by leaving the field off.
 */

import { sha256 } from "@noble/hashes/sha2.js"
import { stableStringify } from "./hash.js"
import { getCrypto, getBase64 } from "./platform.js"
import { getSuite, DEFAULT_ALG } from "./suites/index.js"
import type { Alg } from "./suites/types.js"

/** HTTP methods the request-signing protocol supports. */
export type SignableMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE"

/** The minimal request shape used as input to the signature. */
export interface SignableRequest {
  method: SignableMethod
  pathAndQuery: string
  /**
   * Request body bytes. A string is interpreted as UTF-8. `undefined`
   * is treated as an empty buffer.
   */
  body?: Uint8Array | string
  /**
   * Host the request is targeted at (e.g. `"api.example.com"` or
   * `"api.example.com:8080"`). When the caller signs a request bound to
   * a specific server, this is the host portion of the URL the client
   * will send to. The verifier on the server side reconstructs the same
   * host from the inbound request URL.
   *
   * Always folded into the canonical input as the `h` field; an
   * undefined value here is encoded as `h: ""`.
   */
  host?: string
}

/** Signature bundle attached to an outbound request. */
export interface RequestSignature {
  /** Crypto suite used to produce `sig` (and to reconstruct the canonical input). */
  alg: Alg
  /** Base64-encoded signature under `alg`. */
  sig: string
  /** Unix milliseconds; included verbatim in the canonical input. */
  ts: number
  /** Standard (with padding) base64 of a random 16-byte nonce. */
  nonce: string
}

const DEFAULT_MAX_SKEW_MS = 300_000

// ─── Helpers ─────────────────────────────────────────────────────────────────

function bodyToBytes(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) return new Uint8Array(0)
  if (typeof body === "string") return new TextEncoder().encode(body)
  return body
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

/**
 * Domain-separation tag prepended to a per-request signing input. Binds the
 * signature to the "request" message type by construction so it can never be
 * reinterpreted as a cap-cert or revocation-list signature. Must stay
 * byte-identical across TS, Python, and the test-vector generators.
 */
const REQUEST_SIG_DOMAIN = "starfish-req-v1\n"

/**
 * Canonical UTF-8 string used as the per-request signing input under `alg`:
 * the domain tag {@link REQUEST_SIG_DOMAIN} followed by
 * `stableStringify({alg, m, p, b: sha256hex(bodyBytes), h, ts, nonce})`.
 * `b` is the lowercase hex SHA-256 of the request body bytes; empty body
 * yields the SHA-256 of an empty buffer
 * (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
 * `h` is the host the request is bound to — `req.host ?? ""`. The field
 * is always present, so an attacker who strips the property on the wire
 * still has to forge a signature against `h: ""`. `nonce` is the same
 * base64 string included on the returned signature. `alg` names the crypto
 * suite and is folded in so a signature cannot be downgraded to a weaker
 * scheme. Keys are sorted alphabetically by `stableStringify`, yielding the
 * order `{"alg":…,"b":…,"h":…,"m":…,"nonce":…,"p":…,"ts":…}`.
 */
export function requestSigningCanonicalInput(
  req: SignableRequest,
  ts: number,
  nonceBase64: string,
  alg: Alg,
): string {
  const bodyBytes = bodyToBytes(req.body)
  const bodyHash = bytesToHex(sha256(bodyBytes))
  return (
    REQUEST_SIG_DOMAIN +
    stableStringify({
      alg,
      m: req.method,
      p: req.pathAndQuery,
      b: bodyHash,
      h: req.host ?? "",
      ts,
      nonce: nonceBase64,
    })
  )
}

/**
 * Produce an Ed25519 signature over the canonical request input.
 *
 * Defaults: `ts` is `Date.now()`, `nonce` is 16 random bytes from the
 * configured crypto provider. The returned `nonce` field is the same
 * base64 string used inside the canonical signing input.
 */
export async function signRequest(
  req: SignableRequest,
  devPrivHex: string,
  opts?: { ts?: number; nonce?: Uint8Array; alg?: Alg },
): Promise<RequestSignature> {
  const alg = opts?.alg ?? DEFAULT_ALG
  const ts = opts?.ts ?? Date.now()
  const nonceBytes = opts?.nonce ?? getCrypto().getRandomValues(new Uint8Array(16))
  const nonceB64 = getBase64().encode(nonceBytes)
  const canon = requestSigningCanonicalInput(req, ts, nonceB64, alg)
  const msg = new TextEncoder().encode(canon)
  const sigBytes = getSuite(alg).sign(msg, devPrivHex)
  const sigB64 = getBase64().encode(sigBytes)
  return { alg, sig: sigB64, ts, nonce: nonceB64 }
}

/**
 * Verify a request signature against a signer's Ed25519 public key (hex).
 *
 * The `signature.nonce` and `signature.ts` are folded into the canonical
 * input exactly as on the signing side; tampered fields fail verification.
 * Returns `false` on any cryptographic or decoding error.
 */
export async function verifyRequestSignature(
  req: SignableRequest,
  signature: RequestSignature,
  signerPubHex: string,
): Promise<boolean> {
  try {
    const canon = requestSigningCanonicalInput(req, signature.ts, signature.nonce, signature.alg)
    const msg = new TextEncoder().encode(canon)
    const sigBytes = getBase64().decode(signature.sig)
    return getSuite(signature.alg).verify(sigBytes, msg, signerPubHex)
  } catch {
    return false
  }
}

/**
 * Returns `true` iff `|reqTs - nowMs| <= maxSkewMs`. Default skew is
 * 5 minutes (300_000 ms).
 */
export function isWithinClockSkew(
  reqTs: number,
  nowMs: number,
  maxSkewMs: number = DEFAULT_MAX_SKEW_MS,
): boolean {
  return Math.abs(reqTs - nowMs) <= maxSkewMs
}
