/**
 * v3.0 pairing helpers.
 *
 * Three flows are supported:
 *
 *  1. `bootstrapRootIdentity(passphrase)` — first device of a user. Derives the
 *     root identity from the passphrase and mints a self-signed full-scope
 *     device cap-cert. The "device" IS the root keypair in this case.
 *
 *  2. QR pairing — the new device shows a QR encoding its keypair + requested
 *     scope; the root device assembles a `PairingBundle` (cap-cert + per-
 *     collection wrapped CEKs); the new device installs it.
 *
 *  3. Server-relay pairing — same end-to-end intent as QR, but the QR is
 *     replaced by an encrypted blob sent through a relay. The encryption key
 *     is derived from a short 6-digit code via PBKDF2-HMAC-SHA256.
 *
 * The wrap primitive used inside the bundle is the same HPKE-DHKEM-style
 * construction documented in `keyring.ts`, but the on-the-wire shape is
 * stripped to `{ epoch, ephKem, ct }` — the bundle does not carry the audit
 * signature because the surrounding cap-cert already authenticates the root.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js"
import {
  getBase64,
  getCrypto,
  stableStringify,
  verifyCapCert,
  type CapCert,
} from "@drakkar.software/starfish-protocol"
import { bytesToHex, concat as concatBytes, hexToBytes, hkdfBytes } from "@drakkar.software/starfish-keyring"
import { deriveRootIdentity } from "./identity.js"
import { mintDeviceCap, scopes, type ScopePreset } from "./cap-mint.js"

// ── Types ─────────────────────────────────────────────────────────────────────

export interface DeviceCredentials {
  /** Hex — the user's root Ed25519 public key. */
  rootEdPub: string
  /** Hex 32 — sha256(rootEdPub)[0:32]. */
  userId: string
  device: {
    edPriv: string
    edPub: string
    kemPriv: string
    kemPub: string
  }
  capCert: CapCert
}

export interface PairingQrPayload {
  v: 1
  devEdPub: string
  devKemPub: string
  requestedScope: ScopePreset
  /** Standard base64 (padded) of the 16-byte nonce bytes. */
  qrNonce: string
}

/** Per-collection wrapped CEK. */
export interface WrappedCekEntry {
  epoch: number
  ephKem: string
  ct: string
}

export interface PairingBundle {
  v: 1
  capCert: CapCert
  rootEdPub: string
  wrappedCEKs: Record<string, WrappedCekEntry>
  /**
   * The `qrNonce` from the pairing QR this bundle answers, echoed back so the
   * new device can bind the bundle to the exact pairing session it started.
   * `assemblePairingBundle` always populates it; older bundles may omit it, so
   * `installPairingBundle` only enforces it when the caller passes the nonce it
   * generated.
   */
  qrNonce?: string
}

export interface InstalledPairingResult {
  credentials: DeviceCredentials
  ceks: Record<string, { epoch: number; cek: Uint8Array }>
}

/** Optional knobs for `assemblePairingBundle` — useful for deterministic tests. */
export interface AssemblePairingBundleOpts {
  /**
   * Scope to actually grant the new device, overriding the peer-supplied
   * `parsed.requestedScope`. `requestedScope` arrives from the QR (or relay)
   * and is therefore attacker-influenceable: a tampered or hostile QR could
   * request `rootAll()` and — because a `device` cap binds the resolved
   * identity to the issuer regardless of its paths — obtain a full root proxy.
   * Pass `grantedScope` to bound what the paired device receives (e.g. the
   * scope your UI offered the user); the requested scope is then ignored.
   */
  grantedScope?: ScopePreset
  /** Override the issuer pubkey recorded on each wrapped CEK's audit fields. */
  adderEdPubHex?: string
  /** Cap-cert nbf (unix seconds). */
  nbf?: number
  /** Cap-cert TTL in seconds. */
  ttlSec?: number
  /** Cap-cert nonce bytes (16). */
  certNonce?: Uint8Array
  /** Per-collection deterministic ephemeral private key (32 bytes). */
  ephPrivByCollection?: Record<string, Uint8Array>
  /** Per-collection deterministic AES-GCM IV (12 bytes). */
  ivByCollection?: Record<string, Uint8Array>
}

export interface PairingRequestEncrypted {
  v: 1
  requestNonce: string
  iv: string
  ct: string
}

export interface PairingResponseEncrypted {
  v: 1
  requestNonce: string
  iv: string
  ct: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const ENC = new TextEncoder()
const DEC = new TextDecoder()

/** Salt prefix for code-derived key (deterministic across implementations). */
const CODE_KEY_SALT_PREFIX = ENC.encode("starfish-pair")
/**
 * PBKDF2 iteration count for the relay code-key. Raised to OWASP's 2023
 * SHA-256 floor (600 000). NOTE: no KDF cost rescues a ~20-bit 6-digit code
 * from offline brute force once the relay ciphertext is captured — the iteration
 * count only raises the constant factor. See {@link buildPairingRequest} for the
 * proof-of-possession binding and the security notes in `docs/ts/client/24-pairing.md`
 * (the relay MUST rate-limit / one-shot the code; prefer a longer code or a PAKE
 * for high-threat deployments).
 */
const DEFAULT_PBKDF2_ITERATIONS = 600_000
const WRAP_SALT = ENC.encode("starfish-wrap")
const WRAP_INFO = ENC.encode("starfish-wrap")
const WRAP_IV_BYTES = 12

// ── base64url ─────────────────────────────────────────────────────────────────

function base64UrlEncodeBytes(data: Uint8Array): string {
  const b64 = getBase64().encode(data)
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

function base64UrlDecodeToBytes(encoded: string): Uint8Array {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/")
  const rem = padded.length % 4
  const fullPad = rem === 0 ? padded : padded + "=".repeat(4 - rem)
  return getBase64().decode(fullPad)
}

async function importAesKey(rawKeyBytes: Uint8Array): Promise<CryptoKey> {
  const subtle = getCrypto().subtle
  return subtle.importKey(
    "raw",
    rawKeyBytes as BufferSource,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  )
}

function randomBytes(n: number): Uint8Array {
  return getCrypto().getRandomValues(new Uint8Array(n))
}

// ── Wrap / unwrap primitive (the bare CEK form, no audit fields) ──────────────

/**
 * Reject the all-zero X25519 shared secret produced against a low-order point
 * (RFC 7748 §6.1). The keyring layer applies the same guard; pairing's ECDH must
 * not be the weaker path. Without it, a forged/zeroing `ephKem` could drive a
 * predictable wrap key. The GCM tag would still catch the resulting wrong key,
 * but the explicit check fails closed earlier and keeps the two layers aligned.
 */
function assertNonZeroSharedSecret(secret: Uint8Array): void {
  let acc = 0
  for (let i = 0; i < secret.length; i++) acc |= secret[i]!
  if (acc === 0) throw new Error("Rejected zero X25519 shared secret (small-subgroup attack)")
}

async function wrapCekBare(
  cek: Uint8Array,
  recipientKemPubHex: string,
  ephPriv?: Uint8Array,
  iv?: Uint8Array,
): Promise<{ ephKem: string; ct: string }> {
  const recipientKemPub = hexToBytes(recipientKemPubHex)
  const eph = ephPriv ?? x25519.utils.randomSecretKey()
  const ephPub = x25519.getPublicKey(eph)
  const shared = x25519.getSharedSecret(eph, recipientKemPub)
  assertNonZeroSharedSecret(shared)
  const wrapKeyBytes = await hkdfBytes(shared, WRAP_SALT, WRAP_INFO, 32)
  const wrapKey = await importAesKey(wrapKeyBytes)
  const ivBytes = iv ?? randomBytes(WRAP_IV_BYTES)
  const ctBuf = await getCrypto().subtle.encrypt(
    { name: "AES-GCM", iv: ivBytes as BufferSource },
    wrapKey,
    cek as BufferSource,
  )
  const combined = concatBytes(ivBytes, new Uint8Array(ctBuf))
  return { ephKem: bytesToHex(ephPub), ct: getBase64().encode(combined) }
}

async function unwrapCekBare(
  ephKemHex: string,
  ctB64: string,
  recipientKemPrivHex: string,
): Promise<Uint8Array> {
  const ephPub = hexToBytes(ephKemHex)
  const recipientPriv = hexToBytes(recipientKemPrivHex)
  const shared = x25519.getSharedSecret(recipientPriv, ephPub)
  assertNonZeroSharedSecret(shared)
  const wrapKeyBytes = await hkdfBytes(shared, WRAP_SALT, WRAP_INFO, 32)
  const wrapKey = await importAesKey(wrapKeyBytes)
  const combined = getBase64().decode(ctB64)
  if (combined.length < WRAP_IV_BYTES) {
    throw new Error("Wrapped pairing CEK ciphertext shorter than IV length")
  }
  const iv = combined.slice(0, WRAP_IV_BYTES)
  const ct = combined.slice(WRAP_IV_BYTES)
  try {
    const ptBuf = await getCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      wrapKey,
      ct as BufferSource,
    )
    return new Uint8Array(ptBuf)
  } catch (err) {
    throw new Error("Failed to unwrap pairing CEK: AES-GCM authentication failed", { cause: err })
  }
}

// ── Bootstrap ────────────────────────────────────────────────────────────────

/**
 * First device of a user: derive the root identity from the passphrase and
 * self-sign a full-scope device cap-cert. The returned `device` keys ARE the
 * root keys — there is no distinction at bootstrap time.
 */
export async function bootstrapRootIdentity(passphrase: string): Promise<DeviceCredentials> {
  const root = await deriveRootIdentity(passphrase)
  const capCert = await mintDeviceCap(
    root.keys.edPriv,
    root.keys.edPub,
    { edPubHex: root.keys.edPub, kemPubHex: root.keys.kemPub },
    scopes.rootAll(),
  )
  return {
    rootEdPub: root.keys.edPub,
    userId: root.userId,
    device: {
      edPriv: root.keys.edPriv,
      edPub: root.keys.edPub,
      kemPriv: root.keys.kemPriv,
      kemPub: root.keys.kemPub,
    },
    capCert,
  }
}

// ── QR encoding / parsing ────────────────────────────────────────────────────

/**
 * Encode a pairing QR payload as `base64url(stableStringify(payload))`.
 *
 * `qrNonce` is randomly generated when not provided. Pass an explicit nonce
 * for deterministic tests.
 */
export function buildPairingQr(
  devEdPub: string,
  devKemPub: string,
  requestedScope: ScopePreset,
  qrNonce?: Uint8Array,
): string {
  const nonceBytes = qrNonce ?? randomBytes(16)
  const payload: PairingQrPayload = {
    v: 1,
    devEdPub,
    devKemPub,
    requestedScope,
    qrNonce: getBase64().encode(nonceBytes),
  }
  const canonical = stableStringify(payload as unknown as Record<string, unknown>)
  return base64UrlEncodeBytes(ENC.encode(canonical))
}

/** Decode a QR string produced by `buildPairingQr`. */
export function parsePairingQr(payload: string): PairingQrPayload {
  const bytes = base64UrlDecodeToBytes(payload)
  const json = DEC.decode(bytes)
  const parsed = JSON.parse(json) as PairingQrPayload
  if (parsed.v !== 1) {
    throw new Error(`Unsupported pairing QR version: ${parsed.v as number}`)
  }
  if (typeof parsed.devEdPub !== "string" || typeof parsed.devKemPub !== "string") {
    throw new Error("Pairing QR is missing devEdPub/devKemPub")
  }
  if (typeof parsed.qrNonce !== "string") {
    throw new Error("Pairing QR is missing qrNonce")
  }
  return parsed
}

// ── Bundle assembly (root side) ──────────────────────────────────────────────

/**
 * Root-device side of a pairing exchange.
 *
 * Mints a `device` cap-cert and wraps each in-scope collection's current CEK
 * for the new device's KEM pub. The caller supplies the local map of
 * `{ collection: { epoch, cek } }` from its own keyrings.
 *
 * Fails closed: `opts.grantedScope` is REQUIRED. The peer-supplied
 * `parsed.requestedScope` travels in the QR / relay payload and is therefore
 * attacker-influenceable, and a `device` cap is a root proxy regardless of its
 * paths — so defaulting the grant to the requested scope let a hostile QR mint a
 * full-account proxy. The root must state the scope it grants explicitly.
 */
export async function assemblePairingBundle(
  rootEdKey: { edPriv: string; edPub: string },
  parsed: PairingQrPayload,
  currentEpochByCollection: Record<string, { epoch: number; cek: Uint8Array }>,
  opts: AssemblePairingBundleOpts = {},
): Promise<PairingBundle> {
  if (!opts.grantedScope) {
    throw new Error(
      "assemblePairingBundle: `grantedScope` is required — the QR/relay-supplied " +
        "`requestedScope` is attacker-influenceable and a device cap is a root proxy regardless " +
        "of its paths. Pass an explicit grantedScope to bound the delegated authority.",
    )
  }
  const scopeToGrant = opts.grantedScope
  // mintDeviceCap runs assertCapCertWellFormed internally before signing.
  const capCert = await mintDeviceCap(
    rootEdKey.edPriv,
    rootEdKey.edPub,
    { edPubHex: parsed.devEdPub, kemPubHex: parsed.devKemPub },
    scopeToGrant,
    {
      nbf: opts.nbf,
      ttlSec: opts.ttlSec,
      nonce: opts.certNonce,
    },
  )

  const wrappedCEKs: Record<string, WrappedCekEntry> = {}
  for (const [collection, { epoch, cek }] of Object.entries(currentEpochByCollection)) {
    const ephPriv = opts.ephPrivByCollection?.[collection]
    const iv = opts.ivByCollection?.[collection]
    const { ephKem, ct } = await wrapCekBare(cek, parsed.devKemPub, ephPriv, iv)
    wrappedCEKs[collection] = { epoch, ephKem, ct }
  }

  // adderEdPubHex is accepted by the public signature for future extensibility
  // (e.g., when a non-root admin is reissuing). Currently the cap-cert iss is
  // the source of truth, so we ignore the value here unless callers extend the
  // bundle format. Reference once to keep the option name documented.
  void opts.adderEdPubHex

  return {
    v: 1,
    capCert,
    rootEdPub: rootEdKey.edPub,
    wrappedCEKs,
    qrNonce: parsed.qrNonce,
  }
}

// ── Bundle install (new-device side) ─────────────────────────────────────────

/** Optional knobs for `installPairingBundle`. */
export interface InstallPairingBundleOpts {
  /**
   * Unix seconds used for the cap-cert not-before / expiry window check.
   * Defaults to the current time; override for deterministic tests.
   */
  now?: number
  /**
   * The `qrNonce` this device put in its own pairing QR. When supplied, the
   * bundle's `qrNonce` MUST match it, binding the bundle to this exact pairing
   * session so a replayed/stale bundle captured from another session is
   * rejected. Omit it only for flows that carry no QR (the relay flow already
   * binds the device keys via the request nonce + proof-of-possession).
   */
  expectedQrNonce?: string
  /**
   * The root Ed25519 pubkey (hex) this device expects to be paired to. When
   * supplied, the bundle's `rootEdPub` MUST equal it, so a bundle minted by a
   * *different* root is rejected. Without this pin the device trusts whatever
   * root signed the bundle, which over an open rendezvous lets an attacker's
   * own root provision this device into THEIR account. Pass it whenever the
   * caller already knows the target account's root pubkey (e.g. the user is
   * signed in); when first-contact pairing makes it unknown, surface the
   * bundle's `rootEdPub` fingerprint for the user to compare against the root
   * device instead.
   */
  expectedRootEdPub?: string
}

/**
 * New-device side of the pairing exchange.
 *
 * Fully verifies the cap-cert (signature, not-before / expiry window, and
 * well-formedness), confirms it is a `device` cap issued by the bundle's root
 * for this device's keys, optionally binds it to the pairing session via the
 * QR nonce, then unwraps each wrapped CEK. Throws on any check failure or if an
 * unwrap fails.
 */
export async function installPairingBundle(
  bundle: PairingBundle,
  device: { edPriv: string; edPub: string; kemPriv: string; kemPub: string },
  opts: InstallPairingBundleOpts = {},
): Promise<InstalledPairingResult> {
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  // Full verification: signature + not-before/expiry window + well-formedness.
  // The previous signature-only check accepted expired or not-yet-valid certs.
  const verifyResult = await verifyCapCert(bundle.capCert, { now })
  if (!verifyResult.ok) {
    throw new Error(
      `Pairing bundle cap-cert is invalid: ${verifyResult.reason ?? "unknown"}`,
    )
  }
  // A pairing bundle delivers a device proxy. Rejecting any other kind stops a
  // signed `member` cap (which binds identity to its subject, not the issuer)
  // from being installed and treated as a root-proxy device credential.
  if (bundle.capCert.kind !== "device") {
    throw new Error(
      `Pairing bundle cap-cert must be kind="device", got "${bundle.capCert.kind}"`,
    )
  }
  // The cap-cert must be issued by the root the bundle claims; otherwise the
  // stored credentials would bind a root identity the cert was never signed by.
  if (bundle.capCert.iss !== bundle.rootEdPub) {
    throw new Error("Pairing bundle cap-cert issuer does not match bundle.rootEdPub")
  }
  // Pin the expected root when the caller knows it: rejects a bundle minted by
  // a different root (e.g. an attacker's own root answering an open rendezvous
  // and trying to provision this device into their account).
  if (opts.expectedRootEdPub !== undefined && bundle.rootEdPub !== opts.expectedRootEdPub) {
    throw new Error("Pairing bundle rootEdPub does not match the expected root identity")
  }
  // Sanity: the cap-cert must be for this device's keys.
  if (bundle.capCert.sub !== device.edPub || bundle.capCert.subKem !== device.kemPub) {
    throw new Error("Pairing bundle cap-cert subject does not match this device")
  }
  // Bind the bundle to the pairing session that produced the QR, when known.
  if (opts.expectedQrNonce !== undefined && bundle.qrNonce !== opts.expectedQrNonce) {
    throw new Error("Pairing bundle qrNonce does not match the expected pairing session")
  }

  const ceks: Record<string, { epoch: number; cek: Uint8Array }> = {}
  for (const [collection, entry] of Object.entries(bundle.wrappedCEKs)) {
    const cek = await unwrapCekBare(entry.ephKem, entry.ct, device.kemPriv)
    ceks[collection] = { epoch: entry.epoch, cek }
  }

  const credentials: DeviceCredentials = {
    rootEdPub: bundle.rootEdPub,
    userId: bundle.capCert.issUserId,
    device,
    capCert: bundle.capCert,
  }
  return { credentials, ceks }
}

// ── One-way device provisioning (single blob, root → new device) ─────────────
//
// An alternative to the QR / relay exchanges: the root device plays BOTH roles.
// It generates the new device's keypair, mints its cap (with a caller-chosen
// scope + expiry), and assembles the bundle — all in one step. The new device
// only ever *receives* the result; it sends nothing back.
//
// SECURITY: the new device's PRIVATE keys are generated here, off-device, and
// travel inside `ProvisionedDevice.deviceKeys`. Whoever reads that blob owns a
// full clone of the device (private keys + cap + any wrapped CEKs). Use one-way
// provisioning only over a channel you would trust with the collection keys
// themselves; prefer the two-way QR / relay flow when key exposure is a concern.

/** A freshly generated device keypair (all values hex). */
export interface GeneratedDeviceKeys {
  edPriv: string
  edPub: string
  kemPriv: string
  kemPub: string
}

/** Generate a fresh Ed25519 (sign) + X25519 (KEM) device keypair. */
export function generateDeviceKeys(): GeneratedDeviceKeys {
  const edPriv = ed25519.utils.randomSecretKey()
  const kemPriv = x25519.utils.randomSecretKey()
  return {
    edPriv: bytesToHex(edPriv),
    edPub: bytesToHex(ed25519.getPublicKey(edPriv)),
    kemPriv: bytesToHex(kemPriv),
    kemPub: bytesToHex(x25519.getPublicKey(kemPriv)),
  }
}

/** Options for {@link provisionDevice}. */
export interface ProvisionDeviceOpts {
  /**
   * Caps to grant the provisioned device. REQUIRED — provisioning never
   * defaults to root scope. Use `scopes.rootAll()` for a full account clone
   * (the historic behavior), or a narrower preset to bound what the new device
   * may do.
   */
  scope: ScopePreset
  /**
   * Per-collection current CEKs to wrap into the bundle so the new device can
   * read existing ciphertext immediately. Same `{ collection: { epoch, cek } }`
   * shape `assemblePairingBundle` takes as its third positional argument; here
   * it is an option because `provisionDevice` is single-argument-shaped.
   * Defaults to none (no CEKs travel — add the device as a keyring recipient
   * separately if it must decrypt).
   */
  currentEpochByCollection?: Record<string, { epoch: number; cek: Uint8Array }>
  /** Cap-cert TTL in seconds (`exp = nbf + ttlSec`). Defaults to the mint default (30 days). */
  ttlSec?: number
  /** Cap-cert not-before, unix seconds. Defaults to now. */
  nbf?: number
  /** Cap-cert nonce bytes (16). Provide for deterministic tests. */
  certNonce?: Uint8Array
  /** Pre-generated device keys. Provide for deterministic tests; otherwise fresh keys are generated. */
  deviceKeys?: GeneratedDeviceKeys
  /** Per-collection deterministic ephemeral private key (32 bytes) for the CEK wrap. */
  ephPrivByCollection?: Record<string, Uint8Array>
  /** Per-collection deterministic AES-GCM IV (12 bytes) for the CEK wrap. */
  ivByCollection?: Record<string, Uint8Array>
}

/** Result of {@link provisionDevice}: the new device's keys + its pairing bundle. */
export interface ProvisionedDevice {
  /**
   * The freshly generated device keypair. CONTAINS PRIVATE KEYS — see the
   * security note above. Hand the whole `ProvisionedDevice` to the new device.
   */
  deviceKeys: GeneratedDeviceKeys
  /** The pairing bundle (device cap-cert + wrapped CEKs) for the new device. */
  bundle: PairingBundle
}

/**
 * Root-device side of one-way provisioning. Generates the new device's keypair,
 * mints a `device` cap-cert with the caller-chosen `scope` and expiry, and
 * assembles a pairing bundle wrapping any `currentEpochByCollection` CEKs to the
 * new device's KEM pub. Returns the device keys + bundle as a single blob to
 * hand off (e.g. a setup code).
 *
 * Unlike the QR / relay flows there is no peer-supplied scope to distrust: the
 * scope is whatever the caller passes, bound via `grantedScope`.
 */
export async function provisionDevice(
  rootEdKey: { edPriv: string; edPub: string },
  opts: ProvisionDeviceOpts,
): Promise<ProvisionedDevice> {
  const deviceKeys = opts.deviceKeys ?? generateDeviceKeys()
  const parsed: PairingQrPayload = {
    v: 1,
    devEdPub: deviceKeys.edPub,
    devKemPub: deviceKeys.kemPub,
    requestedScope: opts.scope,
    qrNonce: getBase64().encode(randomBytes(16)),
  }
  const bundle = await assemblePairingBundle(rootEdKey, parsed, opts.currentEpochByCollection ?? {}, {
    grantedScope: opts.scope,
    nbf: opts.nbf,
    ttlSec: opts.ttlSec,
    certNonce: opts.certNonce,
    ephPrivByCollection: opts.ephPrivByCollection,
    ivByCollection: opts.ivByCollection,
  })
  return { deviceKeys, bundle }
}

/**
 * New-device side of one-way provisioning. Installs a {@link ProvisionedDevice}
 * blob: verifies the bundle's cap-cert and unwraps its CEKs exactly as
 * {@link installPairingBundle}, using the device keys carried in the blob.
 */
export async function installProvisionedDevice(
  provisioned: ProvisionedDevice,
  opts: InstallPairingBundleOpts = {},
): Promise<InstalledPairingResult> {
  return installPairingBundle(provisioned.bundle, provisioned.deviceKeys, opts)
}

// ── Server-relay pairing (code-derived encryption) ───────────────────────────

/**
 * Derive a 32-byte symmetric key from a 6-digit (or longer) code via PBKDF2-
 * HMAC-SHA256. Salt is `utf8("starfish-pair") || salt`.
 */
export async function deriveCodeKey(
  code: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  const subtle = getCrypto().subtle as unknown as SubtleCrypto
  const passwordBytes = ENC.encode(code)
  const fullSalt = concatBytes(CODE_KEY_SALT_PREFIX, salt)
  const km = await subtle.importKey(
    "raw",
    passwordBytes as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  )
  const bits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: fullSalt as BufferSource,
      iterations,
    },
    km,
    32 * 8,
  )
  return new Uint8Array(bits)
}

async function aesGcmEncryptWithCodeKey(
  code: string,
  requestNonceBytes: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ iv: string; ct: string }> {
  const keyBytes = await deriveCodeKey(code, requestNonceBytes)
  const key = await importAesKey(keyBytes)
  const iv = randomBytes(WRAP_IV_BYTES)
  const ctBuf = await getCrypto().subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    plaintext as BufferSource,
  )
  return {
    iv: getBase64().encode(iv),
    ct: getBase64().encode(new Uint8Array(ctBuf)),
  }
}

async function aesGcmDecryptWithCodeKey(
  code: string,
  requestNonceBytes: Uint8Array,
  ivB64: string,
  ctB64: string,
): Promise<Uint8Array> {
  const keyBytes = await deriveCodeKey(code, requestNonceBytes)
  const key = await importAesKey(keyBytes)
  const iv = getBase64().decode(ivB64)
  const ct = getBase64().decode(ctB64)
  try {
    const ptBuf = await getCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      key,
      ct as BufferSource,
    )
    return new Uint8Array(ptBuf)
  } catch (err) {
    throw new Error("Failed to decrypt relay payload (wrong code or tampered ciphertext)", {
      cause: err,
    })
  }
}

/**
 * Canonical signing input for the relay request's proof-of-possession.
 * Binds the device's Ed25519 + KEM pubkeys to the request nonce so a relay
 * cannot substitute a `devKemPub` (and harvest the wrapped CEKs) while keeping
 * a `devEdPub` it does not control. `requestNonceB64` is the standard-base64
 * request nonce exactly as it appears on the envelope.
 */
function pairingRequestPopInput(
  devEdPub: string,
  devKemPub: string,
  requestNonceB64: string,
): Uint8Array {
  return ENC.encode(
    stableStringify({ devEdPub, devKemPub, requestNonce: requestNonceB64 } as Record<string, unknown>),
  )
}

/**
 * Build the encrypted pairing request the new device sends through a relay.
 *
 * Plaintext is `stableStringify({ devEdPub, devKemPub, popSig })`, where
 * `popSig` is an Ed25519 proof-of-possession over
 * `{devEdPub, devKemPub, requestNonce}` signed with the device's `edPriv`. The
 * PoP binds the KEM pubkey to the Ed25519 pubkey under a key only the device
 * holds, so a relay cannot swap `devKemPub` for one it controls (which would
 * let it decrypt the bundle's wrapped CEKs) without re-signing.
 *
 * Security: the code-derived AES key still rests on the secrecy and entropy of
 * the short `code`. The PoP does NOT stop an attacker who fully learns the code
 * from substituting BOTH device keys; for that, the relay MUST enforce
 * one-shot use + rate-limiting of the code, and high-threat deployments should
 * use a longer code or a PAKE. See `docs/ts/client/24-pairing.md`.
 */
export async function buildPairingRequest(
  device: { edPriv: string; edPub: string; kemPub: string },
  code: string,
  requestNonce?: Uint8Array,
): Promise<PairingRequestEncrypted> {
  const nonceBytes = requestNonce ?? randomBytes(16)
  const requestNonceB64 = getBase64().encode(nonceBytes)
  const popSig = getBase64().encode(
    ed25519.sign(
      pairingRequestPopInput(device.edPub, device.kemPub, requestNonceB64),
      hexToBytes(device.edPriv),
    ),
  )
  const plaintext = ENC.encode(
    stableStringify({
      devEdPub: device.edPub,
      devKemPub: device.kemPub,
      popSig,
    } as Record<string, unknown>),
  )
  const { iv, ct } = await aesGcmEncryptWithCodeKey(code, nonceBytes, plaintext)
  return {
    v: 1,
    requestNonce: requestNonceB64,
    iv,
    ct,
  }
}

/**
 * Decrypt a relayed pairing request and verify its proof-of-possession.
 *
 * Throws if the payload is missing fields or if `popSig` does not verify
 * against `devEdPub` over `{devEdPub, devKemPub, requestNonce}` — i.e. the
 * request was tampered with (e.g. a relay substituted `devKemPub`).
 */
export async function readPairingRequest(
  encrypted: PairingRequestEncrypted,
  code: string,
): Promise<{ devEdPub: string; devKemPub: string }> {
  const nonceBytes = getBase64().decode(encrypted.requestNonce)
  const pt = await aesGcmDecryptWithCodeKey(code, nonceBytes, encrypted.iv, encrypted.ct)
  const parsed = JSON.parse(DEC.decode(pt)) as {
    devEdPub: string
    devKemPub: string
    popSig?: string
  }
  if (typeof parsed.devEdPub !== "string" || typeof parsed.devKemPub !== "string") {
    throw new Error("Relay request payload missing devEdPub/devKemPub")
  }
  if (typeof parsed.popSig !== "string") {
    throw new Error("Relay request payload missing proof-of-possession signature (popSig)")
  }
  let popOk = false
  try {
    popOk = ed25519.verify(
      getBase64().decode(parsed.popSig),
      pairingRequestPopInput(parsed.devEdPub, parsed.devKemPub, encrypted.requestNonce),
      hexToBytes(parsed.devEdPub),
    )
  } catch {
    popOk = false
  }
  if (!popOk) {
    throw new Error("Relay request proof-of-possession signature is invalid")
  }
  return { devEdPub: parsed.devEdPub, devKemPub: parsed.devKemPub }
}

/**
 * Build the encrypted pairing response the root device sends back through the
 * relay. The plaintext is `stableStringify(bundle)`. The `requestNonce` from
 * the request is echoed back and is also used as the PBKDF2 salt — the two
 * sides MUST agree on it.
 */
export async function buildPairingResponse(
  bundle: PairingBundle,
  code: string,
  requestNonce: string,
): Promise<PairingResponseEncrypted> {
  const nonceBytes = getBase64().decode(requestNonce)
  const plaintext = ENC.encode(stableStringify(bundle as unknown as Record<string, unknown>))
  const { iv, ct } = await aesGcmEncryptWithCodeKey(code, nonceBytes, plaintext)
  return {
    v: 1,
    requestNonce,
    iv,
    ct,
  }
}

/** Decrypt a relayed pairing response. */
export async function readPairingResponse(
  encrypted: PairingResponseEncrypted,
  code: string,
): Promise<PairingBundle> {
  const nonceBytes = getBase64().decode(encrypted.requestNonce)
  const pt = await aesGcmDecryptWithCodeKey(code, nonceBytes, encrypted.iv, encrypted.ct)
  const parsed = JSON.parse(DEC.decode(pt)) as PairingBundle
  return parsed
}

