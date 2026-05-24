"""Generate request-signature.json — canonical request input + Ed25519 sig.

Locks:
- Canonical signing input: stable_stringify({m,p,b: sha256_hex(body),h,ts,nonce}).
- Signature: Ed25519 by the device's `sub` key over UTF-8 of that string.
- ts is unix milliseconds; nonce is base64 of 16 random bytes.
- `h` is the host the request is bound to (e.g. "api.example.com"); empty
  string when no host bind.

Run:
    python3 tests/test-vectors/_generators/request_signature.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _common import ed_sign, ed_verify, load_fixture, stable_stringify  # noqa: E402


_ALG = "ed25519"

# Domain-separation tag — must equal the protocol's _REQUEST_SIG_DOMAIN /
# REQUEST_SIG_DOMAIN (request_signing.py / request-signing.ts). The cross-language
# vector tests fail loudly if it drifts (a mismatched tag → verify fails).
_REQUEST_SIG_DOMAIN = "starfish-req-v1\n"


def _canon(
    method: str,
    path_and_query: str,
    body: bytes,
    ts_ms: int,
    nonce_b64: str,
    host: str = "",
) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return _REQUEST_SIG_DOMAIN + stable_stringify({
        "alg": _ALG,
        "m": method,
        "p": path_and_query,
        "b": body_hash,
        "h": host,
        "ts": ts_ms,
        "nonce": nonce_b64,
    })


def main() -> None:
    laptop = load_fixture("alice_dev_1")

    base_ts = 1_747_000_000_000  # unix ms
    fixed_nonces = [
        base64.b64encode(bytes.fromhex("000102030405060708090a0b0c0d0e0f")).decode(),
        base64.b64encode(bytes.fromhex("10111213141516171819aabbccddeeff")).decode(),
        base64.b64encode(bytes.fromhex("aabbccddeeff00112233445566778899")).decode(),
        base64.b64encode(bytes.fromhex("99887766554433221100ffeeddccbbaa")).decode(),
    ]

    cases = []

    happy_host = "api.example.com"

    # GET /pull/notes/alice/0 — empty body, bound to api.example.com
    canon = _canon(
        "GET",
        "/pull/notes/alice/0?checkpoint=0",
        b"",
        base_ts,
        fixed_nonces[0],
        host=happy_host,
    )
    sig = ed_sign(laptop.ed_priv, canon.encode("utf-8"))
    assert ed_verify(laptop.ed_pub, sig, canon.encode("utf-8"))
    cases.append({
        "label": "pull-empty-body",
        "alg": _ALG,
        "method": "GET",
        "pathAndQuery": "/pull/notes/alice/0?checkpoint=0",
        "bodyUtf8": "",
        "host": happy_host,
        "tsMs": base_ts,
        "nonceBase64": fixed_nonces[0],
        "canonicalSigningInput": canon,
        "signatureBase64": base64.b64encode(sig).decode("ascii"),
        "expectVerify": True,
    })

    # POST /push/notes/alice/0 with JSON body, bound to api.example.com
    push_body = json.dumps({"hello": "world", "n": 7}, separators=(",", ":")).encode("utf-8")
    canon = _canon(
        "POST",
        "/push/notes/alice/0",
        push_body,
        base_ts + 100,
        fixed_nonces[1],
        host=happy_host,
    )
    sig = ed_sign(laptop.ed_priv, canon.encode("utf-8"))
    assert ed_verify(laptop.ed_pub, sig, canon.encode("utf-8"))
    cases.append({
        "label": "push-json-body",
        "alg": _ALG,
        "method": "POST",
        "pathAndQuery": "/push/notes/alice/0",
        "bodyUtf8": push_body.decode("utf-8"),
        "host": happy_host,
        "tsMs": base_ts + 100,
        "nonceBase64": fixed_nonces[1],
        "canonicalSigningInput": canon,
        "signatureBase64": base64.b64encode(sig).decode("ascii"),
        "expectVerify": True,
    })

    # Tampered: same canonical, but signature comes from a different keypair (bob's)
    bob = load_fixture("bob_root")
    canon = _canon(
        "POST",
        "/push/notes/alice/0",
        push_body,
        base_ts + 200,
        fixed_nonces[2],
        host=happy_host,
    )
    bad_sig = ed_sign(bob.ed_priv, canon.encode("utf-8"))
    cases.append({
        "label": "wrong-signer",
        "alg": _ALG,
        "method": "POST",
        "pathAndQuery": "/push/notes/alice/0",
        "bodyUtf8": push_body.decode("utf-8"),
        "host": happy_host,
        "tsMs": base_ts + 200,
        "nonceBase64": fixed_nonces[2],
        "canonicalSigningInput": canon,
        "signatureBase64": base64.b64encode(bad_sig).decode("ascii"),
        "verifyPubkey": "alice_dev_1.edPub",
        "expectVerify": False,
    })

    # Host-mismatch: signed with host A, verifier must use host B → reject.
    signed_host = "api.example.com"
    verify_host = "evil.example.com"
    canon = _canon(
        "POST",
        "/push/notes/alice/0",
        push_body,
        base_ts + 300,
        fixed_nonces[3],
        host=signed_host,
    )
    sig = ed_sign(laptop.ed_priv, canon.encode("utf-8"))
    # Signature is valid against the signed canonical; the test runner must
    # rebuild canonical with `verifyHost` and observe verify == False.
    assert ed_verify(laptop.ed_pub, sig, canon.encode("utf-8"))
    cases.append({
        "label": "host-mismatch",
        "alg": _ALG,
        "method": "POST",
        "pathAndQuery": "/push/notes/alice/0",
        "bodyUtf8": push_body.decode("utf-8"),
        "host": signed_host,
        "verifyHost": verify_host,
        "tsMs": base_ts + 300,
        "nonceBase64": fixed_nonces[3],
        "canonicalSigningInput": canon,
        "signatureBase64": base64.b64encode(sig).decode("ascii"),
        "expectVerify": False,
    })

    out = {
        "description": (
            "Cross-language vector for v3.0 per-request Ed25519 signatures. "
            "Locks the canonical input string and signature for several method/path/body "
            "combinations, plus negative cases for a tampered signer and a host-bind "
            "mismatch. The `h` field in the canonical input pins a signature to a single "
            "server host; verifiers reconstructing canonical with a different host must "
            "fail."
        ),
        "signer": {
            "label": "alice_dev_1",
            "edPub": laptop.ed_pub.hex(),
        },
        "wrongSignerPub": {
            "label": "bob_root",
            "edPub": bob.ed_pub.hex(),
        },
        "cases": cases,
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "request-signature.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
