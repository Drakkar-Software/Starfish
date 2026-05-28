/**
 * Author proof for stored writes (v3.0).
 *
 * Both append-only elements and merge documents can carry an Ed25519 signature
 * over their payload, binding the stored write to the key that produced it.
 * Unlike a per-request signature (which authorizes ONE HTTP call and is then
 * discarded), the author signature is stored WITH the write, so any later reader
 * can verify who wrote it without trusting a self-declared `authorId` field.
 *
 * The signed input binds the author to BOTH the payload AND the document it is
 * written to:
 *
 *     <domain> + stableStringify({ k: documentKey, d: data })
 *
 * `documentKey` is the collection storage path (the server's resolved document
 * key — e.g. `spaces/abc/streams/xyz`; the client derives it by stripping the
 * `/push/` action prefix, the reader by stripping `/pull/`). Binding it stops an
 * authorized writer from lifting another author's signed element (its ciphertext
 * on a private stream, or its plaintext on a public one) and re-appending it
 * under a different key — the signature would no longer match.
 *
 * Two distinct domain tags keep append-element and merge-document signatures from
 * ever cross-verifying, by construction. The canonical input is identical
 * byte-for-byte across TypeScript and Python — locked by the
 * `tests/test-vectors/append-author.json` conformance vector (the doc-author
 * input is the same construction under the `DOC_AUTHOR_DOMAIN` tag).
 *
 * `data` is the payload exactly as stored: the opaque encryptor wrapper for a
 * `delegated` collection, or the plaintext object for a `none` one. The server
 * verifies AFTER `deepSanitize`, over the same bytes it stores, so a reader
 * re-verifying the pulled write always sees a matching signature.
 */

import { AUTHOR_PUBKEY_FIELD, AUTHOR_SIGNATURE_FIELD } from "./constants.js"
import { stableStringify } from "./hash.js"
import { getBase64 } from "./platform.js"
import * as ed25519Suite from "./suites/ed25519.js"

/** Domain tag for an append-only ELEMENT's author signature. Byte-identical
 *  across TS, Python and the vector generators; distinct from every other tag. */
export const APPEND_AUTHOR_DOMAIN = "starfish-append-author-v1\n"

/** Domain tag for a merge-DOCUMENT's author signature. Distinct from
 *  {@link APPEND_AUTHOR_DOMAIN} so an element signature can never verify as a
 *  document signature (or vice versa). */
export const DOC_AUTHOR_DOMAIN = "starfish-doc-author-v1\n"

/** The author-proof fields attached to a write body and stored with it: the
 *  author's Ed25519 public key (hex) and a signature over the canonical input. */
export interface AppendAuthor {
  /** Author's Ed25519 public key (lowercase hex). */
  authorPubkey: string
  /** Base64-encoded Ed25519 signature over the canonical author input. */
  authorSignature: string
}

/** Canonical author signing input: `domain + stableStringify({k: documentKey,
 *  d: data})`. Keys are sorted by `stableStringify`, so the signature is
 *  independent of the JSON key order on the wire. */
function authorCanonicalInput(
  domain: string,
  documentKey: string,
  data: Record<string, unknown>,
): string {
  return domain + stableStringify({ k: documentKey, d: data })
}

function sign(
  domain: string,
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorPrivHex: string,
): AppendAuthor {
  const msg = new TextEncoder().encode(authorCanonicalInput(domain, documentKey, data))
  const sigBytes = ed25519Suite.sign(msg, authorPrivHex)
  return {
    [AUTHOR_PUBKEY_FIELD]: authorPubHex,
    [AUTHOR_SIGNATURE_FIELD]: getBase64().encode(sigBytes),
  }
}

function verify(
  domain: string,
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorSignature: string,
): boolean {
  try {
    const msg = new TextEncoder().encode(authorCanonicalInput(domain, documentKey, data))
    const sigBytes = getBase64().decode(authorSignature)
    return ed25519Suite.verify(sigBytes, msg, authorPubHex)
  } catch {
    return false
  }
}

// ─── Append-only element author proof ──────────────────────────────────────────

/** Canonical input for an append ELEMENT's author signature (see module docs). */
export function appendAuthorCanonicalInput(
  documentKey: string,
  data: Record<string, unknown>,
): string {
  return authorCanonicalInput(APPEND_AUTHOR_DOMAIN, documentKey, data)
}

/** Sign an append element's `data` (bound to `documentKey`) with Ed25519. Returns
 *  the `{authorPubkey, authorSignature}` pair to attach to the append body.
 *  `authorPubHex` MUST be the public key matching `authorPrivHex` (typically the
 *  same key that signs the HTTP request). */
export function signAppendAuthor(
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorPrivHex: string,
): AppendAuthor {
  return sign(APPEND_AUTHOR_DOMAIN, documentKey, data, authorPubHex, authorPrivHex)
}

/** Verify an append element's author signature. Returns `false` on any
 *  cryptographic or decoding error (never throws). */
export function verifyAppendAuthor(
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorSignature: string,
): boolean {
  return verify(APPEND_AUTHOR_DOMAIN, documentKey, data, authorPubHex, authorSignature)
}

// ─── Merge-document author proof ────────────────────────────────────────────────

/** Canonical input for a merge DOCUMENT's author signature (see module docs). */
export function docAuthorCanonicalInput(
  documentKey: string,
  data: Record<string, unknown>,
): string {
  return authorCanonicalInput(DOC_AUTHOR_DOMAIN, documentKey, data)
}

/** Sign a merge document's `data` (bound to `documentKey`) with Ed25519. */
export function signDocAuthor(
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorPrivHex: string,
): AppendAuthor {
  return sign(DOC_AUTHOR_DOMAIN, documentKey, data, authorPubHex, authorPrivHex)
}

/** Verify a merge document's author signature. Returns `false` on any
 *  cryptographic or decoding error (never throws). */
export function verifyDocAuthor(
  documentKey: string,
  data: Record<string, unknown>,
  authorPubHex: string,
  authorSignature: string,
): boolean {
  return verify(DOC_AUTHOR_DOMAIN, documentKey, data, authorPubHex, authorSignature)
}
