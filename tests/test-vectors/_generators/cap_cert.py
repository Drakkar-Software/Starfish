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
    short_user_id,
    stable_stringify,
)

# Domain-separation tag — must equal the protocol's _CAP_CERT_DOMAIN /
# CAP_CERT_DOMAIN (cap.py / cap.ts). The cross-language vector tests fail loudly
# if it drifts (a mismatched tag → the signature no longer verifies).
_CAP_CERT_DOMAIN = "starfish-capcert-v1\n"


def _cap_canon(cert: dict) -> str:
    """Domain-tagged cap-cert canonical signing input: the tag followed by
    stable_stringify of the cert with ``sig`` stripped. Mirrors the protocol's
    ``cap_cert_canonical_signing_input`` byte-for-byte."""
    return _CAP_CERT_DOMAIN + stable_stringify({k: v for k, v in cert.items() if k != "sig"})


def _build_cert(*, kind, iss, iss_user_id, sub, sub_kem, sub_user_id, scope, nbf, exp, nonce_b64):
    cert_no_sig: dict = {
        "v": 1,
        "kind": kind,
        "issAlg": "ed25519",
        "subAlg": "ed25519",
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
        "issAlg": "ed25519",
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


def _build_member_cert_suite(
    *, iss, iss_user_id, sub, sub_user_id, scope, nbf, exp, nonce_b64, sub_alg, sub_kem=None, sub_kem_alg=None
):
    """Build an unsigned ``member`` cap with a non-default subject suite.

    ``issAlg`` stays ``ed25519`` (Alice's root signs the cap); ``subAlg`` names the
    subject's signing suite and ``subKemAlg`` (when set) decouples its KEM suite.
    ``subKem`` is omitted for a same-key KEM suite (secp256k1 reuses its sign key)
    and present for a decoupled KEM. Field insertion order mirrors ``_build_cert``
    so the emitted JSON stays consistent (the signed bytes are sorted-key, so order
    does not affect the signature either way).
    """
    cert_no_sig: dict = {
        "v": 1,
        "kind": "member",
        "issAlg": "ed25519",
        "subAlg": sub_alg,
        "iss": iss,
        "issUserId": iss_user_id,
        "sub": sub,
    }
    if sub_kem_alg is not None:
        cert_no_sig["subKemAlg"] = sub_kem_alg
    if sub_kem is not None:
        cert_no_sig["subKem"] = sub_kem
    cert_no_sig["scope"] = scope
    cert_no_sig["nbf"] = nbf
    cert_no_sig["exp"] = exp
    cert_no_sig["nonce"] = nonce_b64
    cert_no_sig["subUserId"] = sub_user_id
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
    device_canonical = _cap_canon(device_cert)
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
    member_canonical = _cap_canon(member_cert)
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
    aud_open_canonical = _cap_canon(aud_open_cert)
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
    aud_restricted_canonical = _cap_canon(aud_restricted_cert)
    aud_restricted_sig = ed_sign(alice.ed_priv, aud_restricted_canonical.encode("utf-8"))
    aud_restricted_cert["sig"] = base64.b64encode(aud_restricted_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, aud_restricted_sig, aud_restricted_canonical.encode("utf-8"))

    # ── Cross-suite member caps ─────────────────────────────────────────────
    # Lock the canonical byte placement of a NON-ed25519 `subAlg` (and a decoupled
    # `subKemAlg`) cross-language. The issuer stays ed25519 (Alice's root signs),
    # so the cap `sig` is still Ed25519 — only the subject's suite differs. Without
    # these, every `canonicalSigningInput` vector was ed25519-only, so a TS/Python
    # divergence on the new alg fields would go uncaught.
    from coincurve import PublicKeyXOnly  # local: only the cross-suite caps need it

    # Fixed secp256k1 subject scalar (distinct from suite-secp256k1.json fixtures).
    secp_sub_priv = "33" * 32
    secp_sub_pub = PublicKeyXOnly.from_secret(bytes.fromhex(secp_sub_priv)).format().hex()
    secp_sub_user_id = short_user_id(bytes.fromhex(secp_sub_pub))
    notes_scope = {
        "ops": ["read", "write"],
        "collections": ["shared-notes"],
        "paths": ["shared-notes/*"],
    }

    # Pure secp256k1 subject: subAlg = secp256k1-schnorr, KEM reuses the sign key,
    # so `subKem` and `subKemAlg` are BOTH absent (well-formedness requires this).
    nonce_cross = base64.b64encode(bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")).decode()
    cross_cert = _build_member_cert_suite(
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        sub=secp_sub_pub,
        sub_user_id=secp_sub_user_id,
        scope=notes_scope,
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_cross,
        sub_alg="secp256k1-schnorr",
    )
    cross_canonical = _cap_canon(cross_cert)
    cross_sig = ed_sign(alice.ed_priv, cross_canonical.encode("utf-8"))
    cross_cert["sig"] = base64.b64encode(cross_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, cross_sig, cross_canonical.encode("utf-8"))

    # Decoupled KEM: subAlg = secp256k1-schnorr (signing) but subKemAlg = ed25519,
    # so a distinct X25519 `subKem` is present (reuse Bob's X25519 KEM pubkey).
    nonce_mixed = base64.b64encode(bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")).decode()
    mixed_cert = _build_member_cert_suite(
        iss=alice.ed_pub.hex(),
        iss_user_id=alice.user_id,
        sub=secp_sub_pub,
        sub_user_id=secp_sub_user_id,
        scope=notes_scope,
        nbf=nbf,
        exp=exp,
        nonce_b64=nonce_mixed,
        sub_alg="secp256k1-schnorr",
        sub_kem=bob.kem_pub.hex(),
        sub_kem_alg="ed25519",
    )
    mixed_canonical = _cap_canon(mixed_cert)
    mixed_sig = ed_sign(alice.ed_priv, mixed_canonical.encode("utf-8"))
    mixed_cert["sig"] = base64.b64encode(mixed_sig).decode("ascii")
    assert ed_verify(alice.ed_pub, mixed_sig, mixed_canonical.encode("utf-8"))

    # ── Invalid samples (for negative-path tests) ───────────────────────────
    # A forged cert: signature replaced with junk. Must fail verify.
    forged = dict(device_cert)
    forged["sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")

    # Downgrade canaries on the cross-suite member cap (subAlg=secp256k1-schnorr,
    # signed by an ed25519 issuer). Stripping or swapping the signed `subAlg`
    # tag changes the canonical signing input, so the issuer signature no longer
    # verifies — proving the alg-downgrade guard cross-language (not just in the
    # keyring's WrappedKeyEntry). The original `sig` is kept; only the tag moves.
    def _unsigned_canonical(cert: dict) -> bytes:
        return _cap_canon(cert).encode("utf-8")

    stripped_subalg = dict(cross_cert)
    del stripped_subalg["subAlg"]
    assert not ed_verify(alice.ed_pub, cross_sig, _unsigned_canonical(stripped_subalg)), (
        "stripping subAlg unexpectedly still verified — downgrade guard broken"
    )

    swapped_subalg = dict(cross_cert)
    swapped_subalg["subAlg"] = "ed25519"
    assert not ed_verify(alice.ed_pub, cross_sig, _unsigned_canonical(swapped_subalg)), (
        "swapping subAlg to ed25519 unexpectedly still verified — downgrade guard broken"
    )

    out = {
        "description": (
            "Cross-language vector for v3.0 capability certificates. Locks the "
            "canonical signing input (stable_stringify of the cert minus `sig`) "
            "and the Ed25519 signature. Verifies `device` (proxy), `member` "
            "(scoped grant), and `audience` (public-link, no single subject — "
            "open and allow-list-restricted) kinds, plus a forged variant that "
            "must fail signature verification. The audience caps carry no "
            "`sub`/`subKem`/`subUserId`; their absence is part of the locked "
            "canonical input. Two cross-suite member caps (ed25519 issuer, "
            "`secp256k1-schnorr` subject) lock the canonical byte placement of a "
            "non-default `subAlg` and a decoupled `subKemAlg` across languages. "
            "Two downgrade canaries (strippedSubAlgMemberCap / "
            "swappedSubAlgMemberCap) keep the cross-suite cert's signature but "
            "strip/swap the signed `subAlg` tag; both MUST fail signature "
            "verification (expectVerify=false) in both languages."
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
            "secp256k1_sub": {
                "subAlg": "secp256k1-schnorr",
                "pub": secp_sub_pub,
                "userId": secp_sub_user_id,
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
        "crossSuiteMemberCap": {
            "cert": cross_cert,
            "canonicalSigningInput": cross_canonical,
            "signatureBase64": cross_cert["sig"],
            "expectVerify": True,
        },
        "mixedKemMemberCap": {
            "cert": mixed_cert,
            "canonicalSigningInput": mixed_canonical,
            "signatureBase64": mixed_cert["sig"],
            "expectVerify": True,
        },
        "forgedDeviceCap": {
            "cert": forged,
            "canonicalSigningInput": device_canonical,
            "expectVerify": False,
        },
        "strippedSubAlgMemberCap": {
            "cert": stripped_subalg,
            "expectVerify": False,
        },
        "swappedSubAlgMemberCap": {
            "cert": swapped_subalg,
            "expectVerify": False,
        },
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "cap-cert.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
