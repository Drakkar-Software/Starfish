"""Generate cap-cert.json — v3.0 capability-certificate canonical encoding + Ed25519 signature.

Locks:
- The set of cert fields and their canonical signing order (sorted-key
  stable_stringify applied to the cert minus the `sig` field).
- Ed25519 signature over UTF-8 bytes of that canonical string.
- Two kinds: "device" (Alice's laptop, proxy for Alice) and "member"
  (Bob granted scoped access to one of Alice's collections).

Run:
    python3 tests/test-vectors/_generators/cap_cert.py
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from _common import (  # noqa: E402
    ed_sign,
    ed_verify,
    load_fixture,
    stable_stringify,
)


def _build_cert(*, kind, iss, iss_user_id, sub, sub_kem, sub_user_id, scope, nbf, exp, nonce_b64):
    cert_no_sig: dict = {
        "v": 1,
        "kind": kind,
        "iss": iss,
        "issUserId": iss_user_id,
        "sub": sub,
        "subKem": sub_kem,
        "scope": scope,
        "nbf": nbf,
        "exp": exp,
        "nonce": nonce_b64,
    }
    if sub_user_id is not None:
        cert_no_sig["subUserId"] = sub_user_id
    return cert_no_sig


def _build_audience_cert(*, iss, iss_user_id, scope, nbf, exp, nonce_b64, aud=None):
    """Build an unsigned ``audience`` cap (public-link kind).

    Binds NO single subject: ``sub``/``subKem``/``subUserId`` are deliberately
    absent — their presence would change the canonical signing input. ``aud`` is
    omitted for an open link (any identity) and a non-empty list of redeemer
    Ed25519 pubkeys (hex) for a restricted link.
    """
    cert_no_sig: dict = {
        "v": 1,
        "kind": "audience",
        "iss": iss,
        "issUserId": iss_user_id,
        "scope": scope,
        "nbf": nbf,
        "exp": exp,
        "nonce": nonce_b64,
    }
    if aud is not None:
        cert_no_sig["aud"] = aud
    return cert_no_sig


def main() -> None:
    alice = load_fixture("alice_root")
    laptop = load_fixture("alice_dev_1")
    bob = load_fixture("bob_root")

    # Fixed nonces / times so the vector is reproducible.
    nonce_device = base64.b64encode(bytes.fromhex("00112233445566778899aabbccddeeff")).decode()
    nonce_member = base64.b64encode(bytes.fromhex("ffeeddccbbaa99887766554433221100")).decode()
    nbf = 1_747_000_000
    exp = nbf + 30 * 24 * 3600

    # ── Device cap: Alice signs for her laptop ──────────────────────────────
    device_cert = _build_cert(
        kind="device",
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        sub=laptop.ed_pub.hex(),
        sub_kem=laptop.kem_pub.hex(),
        sub_user_id=None,
        scope={
            "ops": ["read", "write", "list"],
            "collections": ["*"],
            "paths": ["*"],
        },
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_device,
    )
    device_canonical = stable_stringify(device_cert)
    device_sig = ed_sign(alice.ed_priv, device_canonical.encode("utf-8"))
    device_cert["sig"] = base64.b64encode(device_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, device_sig, device_canonical.encode("utf-8"))

    # ── Member cap: Alice grants Bob scoped access to "shared-notes" ────────
    member_cert = _build_cert(
        kind="member",
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        sub=bob.ed_pub.hex(),
        sub_kem=bob.kem_pub.hex(),
        sub_user_id=bob.user_id,
        scope={
            "ops": ["read", "write"],
            "collections": ["shared-notes"],
            "paths": ["shared-notes/*"],
        },
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_member,
    )
    member_canonical = stable_stringify(member_cert)
    member_sig = ed_sign(alice.ed_priv, member_canonical.encode("utf-8"))
    member_cert["sig"] = base64.b64encode(member_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, member_sig, member_canonical.encode("utf-8"))

    # ── Audience caps: public-link kind (no single subject) ─────────────────
    nonce_aud_open = base64.b64encode(bytes.fromhex("0a0b0c0d0e0f00112233445566778899")).decode()
    nonce_aud_restricted = base64.b64encode(bytes.fromhex("99887766554433221100ffeeddccbbaa")).decode()
    broadcast_scope = {
        "ops": ["read", "list"],
        "collections": ["broadcast"],
        "paths": ["broadcast/**", "!broadcast/_members"],
    }

    # Open audience cap: no `aud` → any identity may redeem.
    aud_open_cert = _build_audience_cert(
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        scope=broadcast_scope,
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_aud_open,
    )
    aud_open_canonical = stable_stringify(aud_open_cert)
    aud_open_sig = ed_sign(alice.ed_priv, aud_open_canonical.encode("utf-8"))
    aud_open_cert["sig"] = base64.b64encode(aud_open_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, aud_open_sig, aud_open_canonical.encode("utf-8"))

    # Restricted audience cap: only the listed identities may redeem.
    restricted_aud = [bob.ed_pub.hex(), laptop.ed_pub.hex()]
    aud_restricted_cert = _build_audience_cert(
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        scope=broadcast_scope,
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_aud_restricted,
        aud=restricted_aud,
    )
    aud_restricted_canonical = stable_stringify(aud_restricted_cert)
    aud_restricted_sig = ed_sign(alice.ed_priv, aud_restricted_canonical.encode("utf-8"))
    aud_restricted_cert["sig"] = base64.b64encode(aud_restricted_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, aud_restricted_sig, aud_restricted_canonical.encode("utf-8"))

    # ── Invalid samples (for negative-path tests) ───────────────────────────
    # A forged cert: signature replaced with junk. Must fail verify.
    forged = dict(device_cert)
    forged["sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")

    out = {
        "description": (
            "Cross-language vector for v3.0 capability certificates. Locks the "
            "canonical signing input (stable_stringify of the cert minus `sig`) "
            "and the Ed25519 signature. Verifies `device` (proxy), `member` "
            "(scoped grant), and `audience` (public-link, no single subject — "
            "open and allow-list-restricted) kinds, plus a forged variant that "
            "must fail signature verification. The audience caps carry no "
            "`sub`/`subKem`/`subUserId`; their absence is part of the locked "
            "canonical input."
        ),
        "issuer": {
            "label": "alice_root",
            "edPub": alice.ed_pub.hex(),
            "userId": alice.user_id,
        },
        "subjects": {
            "alice_dev_1": {
                "edPub": laptop.ed_pub.hex(),
                "kemPub": laptop.kem_pub.hex(),
            },
            "bob_root": {
                "edPub": bob.ed_pub.hex(),
                "kemPub": bob.kem_pub.hex(),
                "userId": bob.user_id,
            },
        },
        "deviceCap": {
            "cert": device_cert,
            "canonicalSigningInput": device_canonical,
            "signatureBase64": device_cert["sig"],
            "expectVerify": True,
        },
        "memberCap": {
            "cert": member_cert,
            "canonicalSigningInput": member_canonical,
            "signatureBase64": member_cert["sig"],
            "expectVerify": True,
        },
        "audienceCapOpen": {
            "cert": aud_open_cert,
            "canonicalSigningInput": aud_open_canonical,
            "signatureBase64": aud_open_cert["sig"],
            "expectVerify": True,
        },
        "audienceCapRestricted": {
            "cert": aud_restricted_cert,
            "canonicalSigningInput": aud_restricted_canonical,
            "signatureBase64": aud_restricted_cert["sig"],
            "audience": restricted_aud,
            "expectVerify": True,
        },
        "forgedDeviceCap": {
            "cert": forged,
            "canonicalSigningInput": device_canonical,
            "expectVerify": False,
        },
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "cap-cert.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
