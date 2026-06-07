# starfish-protocol

Shared protocol primitives for [Starfish](../../../README.md) — the on-the-wire shapes that the Python client and server agree on, byte-for-byte parity with the TypeScript `@drakkar.software/starfish-protocol` package.

This package has **no I/O**. It only exposes canonical encoding, hashing, capability-certificate signing, and per-request signing helpers.

## Install

```bash
pip install starfish-protocol
```

## What's in v3.0

The v3 protocol is built around two signed envelopes — **capability certificates** (long-lived, scoped grants of authority) and **per-request signatures** (per-call freshness + replay protection). Everything else in this package supports those two.

| Export | Kind | Purpose |
|---|---|---|
| `stable_stringify(value)` | function | Canonical UTF-8 JSON: recursively sorted keys, no whitespace. The signing input for both cap-certs and per-request signatures runs through this. |
| `compute_hash(data)` | function | SHA-256 over `stable_stringify(data)`, lowercase hex. The hash that backs `baseHash` optimistic concurrency. |
| `deep_merge(local, remote)` | function | Default remote-wins deep-merge resolver. Lists are atomic. |
| `sign_cap_cert`, `verify_cap_cert`, `verify_cap_cert_signature`, `assert_cap_cert_well_formed`, `cap_cert_canonical_signing_input` | functions | Cap-cert minting/validation. |
| `is_root_device_cap(cert)` | function | True for a self-signed root-device cap (`kind:"device"`, `iss===sub`). |
| `sign_request`, `verify_request_signature`, `request_signing_canonical_input`, `is_within_clock_skew` | functions | Per-request Ed25519 signing + ±5 min clock-skew check. |
| `build_revocation_list`, `revocation_list_canonical_signing_input` | functions | Mint a signed revocation list (`{v, iss, issUserId, generation, revoked, revokedSubjects?, sig}`) from an issuer keypair; `issUserId = sha256(edPub)[0:32]`. Locked by `revocation-list.json`. |
| `IV_BYTES`, `ENCRYPTED_KEY`, `_derive_key` | constants/util | HKDF-SHA256 → AES-256-GCM building block used by `"delegated"` mode wrap/unwrap. |
| `CapCert`, `CapKind`, `CapScope` | dataclasses | Cap-cert object model. |
| `RequestSignature` | dataclass | Per-request signature bundle. |
| `Timestamps`, `PullResult`, `PushSuccess` | dataclasses | Protocol response shapes shared with client/server. |
| `CORS_ALLOW_HEADERS` | constant | Canonical list of non-simple request headers (`Authorization`, `Content-Type`, the `X-Starfish-*` auth headers, plus `X-Requested-With`) a server should advertise in `Access-Control-Allow-Headers`. Built from the `HEADER_*` constants so it cannot drift. |

## Capability certificates

A cap-cert is a small JSON object signed by the user's root Ed25519 key. It declares: *subject `S` may perform ops `O` on collections/paths `P` until `exp`*. Every authenticated request carries one.

```python
from starfish_protocol import (
    CapCert,
    sign_cap_cert,
    verify_cap_cert,
    cap_cert_canonical_signing_input,
)

unsigned = {
    "v": 1,
    "kind": "device",
    "iss":        root_ed_pub_hex,
    "issUserId":  root_user_id_hex,
    "sub":        device_ed_pub_hex,
    "subKem":     device_kem_pub_hex,
    "scope": {
        "ops":         ["read", "write", "list"],
        "collections": ["notes"],
        "paths":       ["notes/*", "!notes/_keyring"],
    },
    "nbf": now_sec,
    "exp": now_sec + 30 * 24 * 3600,
    "nonce": base64(random_bytes(16)),
}
cap = sign_cap_cert(unsigned, root_ed_priv_hex)

# Server side
result = verify_cap_cert(cap, now=time.time(), clock_skew_sec=300)
# → CapCertVerifyResult(ok=True) | CapCertVerifyResult(ok=False, code="BAD_SIG" | "EXPIRED" | …)
```

Two kinds:

- `kind: "device"` — subject acts as a proxy for the issuer; `auth.identity` resolves to `issUserId`. Wildcards allowed.
- `kind: "member"` — subject keeps its own `auth.identity = subUserId`; the cap adds collection-scoped roles only. Wildcards forbidden; cannot grant access into the issuer's own `users/<issUserId>/*` namespace. These rules are enforced both at mint time (`assert_cap_cert_well_formed`) and at every request (`verify_cap_cert` step 4).

Full schema, role synthesis, and rotation: [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md).

## Canonical encoding

Both signing inputs (`cap_cert_canonical_signing_input` and `request_signing_canonical_input`) follow the same rule: produce a value, strip the `sig` field if present, run it through `stable_stringify`, and sign the UTF-8 bytes.

`stable_stringify` is the single canonicalization primitive: every dict key, at every nesting level, is sorted lexicographically; lists preserve order; no whitespace. Two implementations that agree on `stable_stringify` agree on every higher-level signature.

## Per-request signing

Every authenticated HTTP request carries an Ed25519 signature over `(method, pathAndQuery, sha256(body), ts, nonce)`. The canonical input is `stable_stringify({"m": ..., "p": ..., "b": ..., "ts": ..., "nonce": ...})` where `b` is the lowercase hex SHA-256 of the body bytes (empty body yields `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

```python
from starfish_protocol import sign_request, verify_request_signature, is_within_clock_skew

sig = sign_request(
    {"method": "POST", "path_and_query": "/v1/push/notes/abc", "body": b'{"theme":"dark"}'},
    dev_ed_priv_hex,
)
# sig = RequestSignature(sig="base64...", ts=1730000000000, nonce="base64...")

# Server side
ok = verify_request_signature(req, sig, dev_ed_pub_hex)
fresh = is_within_clock_skew(sig.ts, now_ms=time.time() * 1000, max_skew_ms=300_000)  # ±5 min
```

The matching headers on the wire are `X-Starfish-Sig`, `X-Starfish-Ts`, `X-Starfish-Nonce`. The server pairs verification with an LRU nonce cache to prevent replay (see [`starfish-server`](../server/README.md)).

## Cross-language test vectors

This package is pinned to TypeScript's `@drakkar.software/starfish-protocol` via JSON fixtures in [`tests/test-vectors/`](../../../tests/test-vectors/). The relevant files for v3:

- `hash.json` / `crypto.json` — `compute_hash`, `_derive_key`, AES-GCM.
- `identity-derivation.json` — passphrase → root Ed25519/X25519 keys.
- `multi-recipient-wrap.json` — keyring wrap entries.
- `pairing-bundle.json` — full QR pairing roundtrip.
- `request-signature.json` — canonical input + Ed25519 signature.

Both implementations must produce byte-identical results for every fixture.

## See also

- [Migration v2 → v3](../../../docs/migration/v2-to-v3.md) — what changed in the protocol surface.
- [docs/ts/client/25-capability-certs.md](../../../docs/ts/client/25-capability-certs.md) — cap-cert design.
- [docs/ts/client/23-multi-recipient-delegated.md](../../../docs/ts/client/23-multi-recipient-delegated.md) — keyring shape.
