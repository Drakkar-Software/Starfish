# @drakkar.software/starfish-protocol

Shared protocol primitives for [Starfish](../../../README.md) — the on-the-wire shapes that the TypeScript client and server agree on, byte-for-byte parity with the Python `starfish-protocol` package.

This package has **no I/O**. It only exposes canonical encoding, hashing, capability-certificate signing, and per-request signing helpers.

## Install

```bash
pnpm add @drakkar.software/starfish-protocol
```

## What's in v3.0

The v3 protocol is built around two signed envelopes — **capability certificates** (long-lived, scoped grants of authority) and **per-request signatures** (per-call freshness + replay protection). Everything else in this package supports those two.

| Export | Kind | Purpose |
|---|---|---|
| `stableStringify(value)` | function | Canonical UTF-8 JSON: recursively sorted keys, no whitespace. The signing input for both cap-certs and per-request signatures runs through this. |
| `computeHash(data)` | function | SHA-256 over `stableStringify(data)`, lowercase hex. The hash that backs `baseHash` optimistic concurrency. |
| `deepMerge(local, remote)` | function | Default remote-wins deep-merge resolver. Arrays are atomic. |
| `configurePlatform`, `getCrypto`, `getBase64` | functions | Polyfill hooks for environments without the Web Crypto API (React Native, older runtimes). |
| `signCapCert`, `verifyCapCert`, `verifyCapCertSignature`, `assertCapCertWellFormed`, `capCertCanonicalSigningInput` | functions | Cap-cert minting/validation. |
| `isRootDeviceCap(cert)` | function | True for a self-signed root-device cap (`kind:"device"`, `iss===sub`). |
| `signRequest`, `verifyRequestSignature`, `requestSigningCanonicalInput`, `isWithinClockSkew` | functions | Per-request Ed25519 signing + ±5 min clock-skew check. |
| `buildRevocationList`, `revocationListCanonicalSigningInput` | functions | Mint a signed `RevocationList` (`{v, iss, issUserId, generation, revoked, revokedSubjects?, sig}`) from an issuer keypair; `issUserId = sha256(edPub)[0:32]`. Locked by `revocation-list.json`. |
| `RevocationList`, `RevocationEntry`, `RevokedSubject`, `BuildRevocationListOpts` | types | Revocation-list object model. |
| `deriveKey`, `IV_BYTES`, `ENCRYPTED_KEY` | constants/util | HKDF-SHA256 → AES-256-GCM building block used by `"delegated"` mode wrap/unwrap. |
| `CapCert`, `CapKind`, `CapScope`, `UnsignedCapCert`, `CapCertVerifyResult`, `CapCertWellFormedCode` | types | Cap-cert object model. |
| `SignableMethod`, `SignableRequest`, `RequestSignature` | types | Per-request signature inputs and result bundle. |
| `PullResult`, `PushSuccess` | types | Protocol response shapes shared with client/server. |
| `CORS_ALLOW_HEADERS` | constant | Canonical list of non-simple request headers (`Authorization`, `Content-Type`, the `X-Starfish-*` auth headers, plus `X-Requested-With`) a server should advertise in `Access-Control-Allow-Headers`. Built from the `HEADER_*` constants so it cannot drift. |

## Capability certificates

A cap-cert is a small JSON object signed by the user's root Ed25519 key. It declares: *subject `S` may perform ops `O` on collections/paths `P` until `exp`*. Every authenticated request carries one.

```ts
import {
  signCapCert,
  verifyCapCert,
  capCertCanonicalSigningInput,
  type CapCert,
  type UnsignedCapCert,
} from "@drakkar.software/starfish-protocol"

const unsigned: UnsignedCapCert = {
  v: 1,
  kind: "device",
  iss:       rootEdPubHex,
  issUserId: rootUserIdHex,
  sub:       deviceEdPubHex,
  subKem:    deviceKemPubHex,
  scope: {
    ops:         ["read", "write", "list"],
    collections: ["notes"],
    paths:       ["notes/*", "!notes/_keyring"],
  },
  nbf: nowSec,
  exp: nowSec + 30 * 24 * 3600,
  nonce: base64(randomBytes(16)),
}
const cap: CapCert = await signCapCert(unsigned, rootEdPrivHex)

// Server side
const result = await verifyCapCert(cap, { now: Date.now() / 1000, clockSkewSec: 300 })
// → { ok: true } | { ok: false, code: "BAD_SIG" | "EXPIRED" | "BAD_USER_ID" | … }
```

Two kinds:

- `kind: "device"` — subject acts as a proxy for the issuer; `auth.identity` resolves to `issUserId`. Wildcards allowed.
- `kind: "member"` — subject keeps its own `auth.identity = subUserId`; the cap adds collection-scoped roles only. Wildcards forbidden; cannot grant access into the issuer's own `users/<issUserId>/*` namespace. These rules are enforced both at mint time (`assertCapCertWellFormed`) and at every request (`verifyCapCert` step 4).

Full schema, role synthesis, and rotation: [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md).

## Canonical encoding

Both signing inputs (`capCertCanonicalSigningInput` and `requestSigningCanonicalInput`) follow the same rule: produce a value, strip the `sig` field if present, run it through `stableStringify`, and sign the UTF-8 bytes.

`stableStringify` is the single canonicalization primitive: every object key, at every nesting level, is sorted lexicographically; arrays preserve order; no whitespace. Two implementations that agree on `stableStringify` agree on every higher-level signature.

## Per-request signing

Every authenticated HTTP request carries an Ed25519 signature over `(method, pathAndQuery, sha256(body), ts, nonce)`. The canonical input is `stableStringify({m, p, b, ts, nonce})` where `b` is the lowercase hex SHA-256 of the body bytes (empty body yields `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

```ts
import { signRequest, verifyRequestSignature, isWithinClockSkew } from "@drakkar.software/starfish-protocol"

const sig = await signRequest(
  { method: "POST", pathAndQuery: "/v1/push/notes/abc", body: '{"theme":"dark"}' },
  devEdPrivHex,
)
// sig = { sig: "base64...", ts: 1730000000000, nonce: "base64..." }

// Server side
const ok = await verifyRequestSignature(req, sig, devEdPubHex)
const fresh = isWithinClockSkew(sig.ts, Date.now(), 300_000)  // ±5 min default
```

The matching headers on the wire are `X-Starfish-Sig`, `X-Starfish-Ts`, `X-Starfish-Nonce`. The server pairs verification with an LRU nonce cache to prevent replay (see [`@drakkar.software/starfish-server`](../server/README.md)).

## Cross-language test vectors

This package is pinned to Python's `starfish-protocol` via JSON fixtures in [`tests/test-vectors/`](../../../tests/test-vectors/). The relevant files for v3:

- `hash.json` / `crypto.json` — `computeHash`, `deriveKey`, AES-GCM.
- `identity-derivation.json` — passphrase → root Ed25519/X25519 keys.
- `multi-recipient-wrap.json` — keyring wrap entries.
- `pairing-bundle.json` — full QR pairing roundtrip.
- `request-signature.json` — canonical input + Ed25519 signature.

Both implementations must produce byte-identical results for every fixture.

## See also

- [Migration v2 → v3](../../../docs/migration/v2-to-v3.md) — what changed in the protocol surface.
- [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md) — cap-cert design.
- [docs/ts/client/23-multi-recipient-delegated.md](../../../docs/ts/client/23-multi-recipient-delegated.md) — keyring shape.
