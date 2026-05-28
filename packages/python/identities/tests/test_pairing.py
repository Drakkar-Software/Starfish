"""v3.0 pairing helpers — cross-language vector + behavioral tests.

Mirrors the TypeScript ``pairing.test.ts``: locks the QR encoding and bundle
install roundtrip against ``tests/test-vectors/pairing-bundle.json`` and
exercises ``bootstrap_root_identity`` + the server-relay request/response
encryption with a 6-digit code.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from starfish_protocol.cap import sign_cap_cert, verify_cap_cert, verify_cap_cert_signature
from starfish_identities.identity import derive_root_identity
from starfish_identities.cap_mint import scopes
from starfish_identities.pairing import (
    PairingBundle,
    PairingQrPayload,
    AssemblePairingBundleOpts,
    ProvisionDeviceOpts,
    ProvisionedDevice,
    assemble_pairing_bundle,
    bootstrap_root_identity,
    build_pairing_qr,
    build_pairing_request,
    build_pairing_response,
    derive_code_key,
    generate_device_keys,
    install_pairing_bundle,
    install_provisioned_device,
    parse_pairing_qr,
    provision_device,
    read_pairing_request,
    read_pairing_response,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "pairing-bundle.json"
)
V = json.loads(VECTORS_PATH.read_text())


# ── QR encoding ───────────────────────────────────────────────────────────────


def test_build_pairing_qr_reproduces_vector_base64url() -> None:
    qr_nonce_bytes = base64.b64decode(V["qrPayload"]["object"]["qrNonce"])
    encoded = build_pairing_qr(
        V["newDevice"]["edPub"],
        V["newDevice"]["kemPub"],
        V["qrPayload"]["object"]["requestedScope"],
        qr_nonce=qr_nonce_bytes,
    )
    assert encoded == V["qrPayload"]["base64UrlEncoded"]


def test_parse_pairing_qr_decodes_vector_object() -> None:
    parsed = parse_pairing_qr(V["qrPayload"]["base64UrlEncoded"])
    assert parsed.to_dict() == V["qrPayload"]["object"]


def test_build_parse_qr_roundtrip_with_synthetic_nonce() -> None:
    nonce = bytes(range(16))
    scope = {"ops": ["read"], "collections": ["notes"], "paths": ["notes/*"]}
    encoded = build_pairing_qr("aa" * 32, "bb" * 32, scope, qr_nonce=nonce)
    parsed = parse_pairing_qr(encoded)
    assert parsed.v == 1
    assert parsed.dev_ed_pub == "aa" * 32
    assert parsed.dev_kem_pub == "bb" * 32
    assert parsed.requested_scope == scope
    assert parsed.qr_nonce == base64.b64encode(nonce).decode("ascii")


# ── Bundle install roundtrip ──────────────────────────────────────────────────


def test_install_pairing_bundle_recovers_ceks_for_each_collection() -> None:
    bundle = PairingBundle.from_dict(V["bundle"])
    device = {
        "edPriv": V["newDevice"]["edPriv"],
        "edPub": V["newDevice"]["edPub"],
        "kemPriv": V["newDevice"]["kemPriv"],
        "kemPub": V["newDevice"]["kemPub"],
    }
    # The vector cap-cert has fixed nbf/exp; evaluate the window within it.
    result = install_pairing_bundle(bundle, device, now=bundle.cap_cert["nbf"] + 5)

    assert result.credentials.root_ed_pub == V["root"]["edPub"]
    assert result.credentials.user_id == V["root"]["userId"]
    assert result.credentials.device["edPub"] == V["newDevice"]["edPub"]
    assert result.credentials.device["kemPub"] == V["newDevice"]["kemPub"]
    assert result.credentials.cap_cert == V["bundle"]["capCert"]

    for check in V["unwrapChecks"]:
        recovered = result.ceks[check["collection"]]
        assert recovered.epoch == V["bundle"]["wrappedCEKs"][check["collection"]]["epoch"]
        assert recovered.cek.hex() == check["expectedCekHex"]


def test_install_pairing_bundle_rejects_tampered_signature() -> None:
    bundle_dict = json.loads(json.dumps(V["bundle"]))
    sig = bundle_dict["capCert"]["sig"]
    bundle_dict["capCert"]["sig"] = ("B" if sig[0] == "A" else "A") + sig[1:]
    bundle = PairingBundle.from_dict(bundle_dict)
    device = {
        "edPriv": V["newDevice"]["edPriv"],
        "edPub": V["newDevice"]["edPub"],
        "kemPriv": V["newDevice"]["kemPriv"],
        "kemPub": V["newDevice"]["kemPub"],
    }
    with pytest.raises(ValueError):
        install_pairing_bundle(bundle, device, now=bundle.cap_cert["nbf"] + 5)


# ── bootstrap_root_identity ───────────────────────────────────────────────────


def test_bootstrap_root_identity_userid_matches_alice_fixture() -> None:
    creds = bootstrap_root_identity("alice-root-passphrase")
    root = derive_root_identity("alice-root-passphrase")
    assert creds.user_id == root.user_id
    assert creds.user_id == V["root"]["userId"]
    assert creds.root_ed_pub == root.keys.ed_pub
    assert creds.device["edPub"] == root.keys.ed_pub
    assert creds.device["kemPub"] == root.keys.kem_pub
    assert creds.cap_cert["kind"] == "device"
    assert creds.cap_cert["iss"] == root.keys.ed_pub
    assert creds.cap_cert["sub"] == root.keys.ed_pub
    assert creds.cap_cert["subKem"] == root.keys.kem_pub
    # Full verify — bootstrap's nbf is set to now.
    result = verify_cap_cert(creds.cap_cert, now=creds.cap_cert["nbf"] + 5)
    assert result["ok"] is True


def test_bootstrap_rejects_empty_passphrase() -> None:
    with pytest.raises(ValueError):
        bootstrap_root_identity("")


# ── assemble_pairing_bundle → install_pairing_bundle roundtrip ────────────────


def test_assemble_then_install_roundtrip_recovers_supplied_ceks() -> None:
    root = derive_root_identity("alice-root-passphrase")
    new_device = {
        "edPriv": V["newDevice"]["edPriv"],
        "edPub": V["newDevice"]["edPub"],
        "kemPriv": V["newDevice"]["kemPriv"],
        "kemPub": V["newDevice"]["kemPub"],
    }
    scope = V["qrPayload"]["object"]["requestedScope"]
    qr = build_pairing_qr(new_device["edPub"], new_device["kemPub"], scope)
    parsed = parse_pairing_qr(qr)

    cek_a = b"\xaa" * 32
    cek_b = b"\xbb" * 32

    bundle = assemble_pairing_bundle(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        parsed,
        {
            "notes": {"epoch": 3, "cek": cek_a},
            "tasks": {"epoch": 7, "cek": cek_b},
        },
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    assert bundle.root_ed_pub == root.keys.ed_pub
    assert bundle.cap_cert["kind"] == "device"
    assert bundle.cap_cert["iss"] == root.keys.ed_pub
    assert bundle.cap_cert["sub"] == new_device["edPub"]
    assert verify_cap_cert_signature(bundle.cap_cert) is True

    installed = install_pairing_bundle(bundle, new_device)
    assert installed.ceks["notes"].cek == cek_a
    assert installed.ceks["notes"].epoch == 3
    assert installed.ceks["tasks"].cek == cek_b
    assert installed.ceks["tasks"].epoch == 7


# ── provision_device (one-way) → install_provisioned_device ───────────────────


def test_provision_device_mints_chosen_scope_exp_and_installs() -> None:
    root = derive_root_identity("alice-root-passphrase")
    cek = b"\xcd" * 32
    nbf = 1_700_000_000

    provisioned = provision_device(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        ProvisionDeviceOpts(
            scope=scopes.root_all(),
            current_epoch_by_collection={"notes": {"epoch": 5, "cek": cek}},
            nbf=nbf,
            ttl_sec=3600,
        ),
    )

    # A fresh device keypair was generated (32-byte hex keys).
    assert len(provisioned.device_keys["edPub"]) == 64
    assert len(provisioned.device_keys["kemPub"]) == 64

    cert = provisioned.bundle.cap_cert
    assert cert["kind"] == "device"
    assert cert["iss"] == root.keys.ed_pub
    assert cert["sub"] == provisioned.device_keys["edPub"]
    assert cert["scope"] == scopes.root_all()
    assert cert["nbf"] == nbf
    assert cert["exp"] == nbf + 3600

    installed = install_provisioned_device(provisioned, now=nbf + 5)
    assert installed.credentials.user_id == cert["issUserId"]
    assert installed.ceks["notes"].cek == cek
    assert installed.ceks["notes"].epoch == 5


def test_provision_device_bounds_restricted_scope() -> None:
    root = derive_root_identity("alice-root-passphrase")
    read_only = {"ops": ["read", "list"], "collections": ["chat"], "paths": ["chat/rooms/general"]}
    provisioned = provision_device(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        ProvisionDeviceOpts(scope=read_only),
    )
    assert provisioned.bundle.cap_cert["scope"]["ops"] == ["read", "list"]
    assert "write" not in provisioned.bundle.cap_cert["scope"]["ops"]


def test_provision_device_reuses_injected_keys_and_roundtrips_dict() -> None:
    root = derive_root_identity("alice-root-passphrase")
    device_keys = generate_device_keys()
    provisioned = provision_device(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        ProvisionDeviceOpts(scope=scopes.root_all(), device_keys=device_keys),
    )
    assert provisioned.device_keys == device_keys
    assert provisioned.bundle.cap_cert["sub"] == device_keys["edPub"]
    assert provisioned.bundle.cap_cert["subKem"] == device_keys["kemPub"]
    # to_dict / from_dict round-trips (serialization parity with the TS blob shape).
    assert ProvisionedDevice.from_dict(provisioned.to_dict()).device_keys == device_keys


# ── install_pairing_bundle hardening (kind / window / session binding) ────────


def _new_device() -> dict[str, str]:
    return {
        "edPriv": V["newDevice"]["edPriv"],
        "edPub": V["newDevice"]["edPub"],
        "kemPriv": V["newDevice"]["kemPriv"],
        "kemPub": V["newDevice"]["kemPub"],
    }


def test_install_rejects_member_cap() -> None:
    root = derive_root_identity("alice-root-passphrase")
    member = derive_root_identity("bob-root-passphrase")
    now = 1_000_000
    # A well-formed, validly-signed member cap whose subject is this device. It
    # passes verify_cap_cert (generic well-formedness); the kind guard rejects it.
    member_cert = sign_cap_cert(
        {
            "v": 1,
            "kind": "member",
            "iss": root.keys.ed_pub,
            "issUserId": root.user_id,
            "sub": member.keys.ed_pub,
            "subKem": member.keys.kem_pub,
            "subUserId": member.user_id,
            "scope": {"ops": ["read"], "collections": ["notes"], "paths": ["notes/**", "!notes/_members"]},
            "nbf": now,
            "exp": now + 1000,
            "nonce": base64.b64encode(bytes(16)).decode("ascii"),
        },
        root.keys.ed_priv,
    )
    bundle = PairingBundle(cap_cert=member_cert, root_ed_pub=root.keys.ed_pub, wrapped_ceks={})
    member_device = {
        "edPriv": member.keys.ed_priv,
        "edPub": member.keys.ed_pub,
        "kemPriv": member.keys.kem_priv,
        "kemPub": member.keys.kem_pub,
    }
    with pytest.raises(ValueError, match='kind="device"'):
        install_pairing_bundle(bundle, member_device, now=now + 5)


def test_install_rejects_expired_bundle() -> None:
    from starfish_identities.pairing import AssemblePairingBundleOpts

    root = derive_root_identity("alice-root-passphrase")
    device = _new_device()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], V["qrPayload"]["object"]["requestedScope"])
    parsed = parse_pairing_qr(qr)
    nbf = 1_000_000
    bundle = assemble_pairing_bundle(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        parsed,
        {},
        AssemblePairingBundleOpts(nbf=nbf, ttl_sec=10, granted_scope=parsed.requested_scope),
    )
    # Past exp + 300s clock skew → rejected.
    with pytest.raises(ValueError, match="invalid"):
        install_pairing_bundle(bundle, device, now=nbf + 10 + 301)
    # Inside the window it still installs.
    ok = install_pairing_bundle(bundle, device, now=nbf + 5)
    assert ok.credentials.device["edPub"] == device["edPub"]


def test_assemble_grants_granted_scope_over_requested() -> None:
    from starfish_identities.pairing import AssemblePairingBundleOpts

    root = derive_root_identity("alice-root-passphrase")
    device = _new_device()
    # Hostile/tampered QR requests root-all access.
    requested = {"ops": ["read", "list", "write"], "collections": ["*"], "paths": ["**"]}
    qr = build_pairing_qr(device["edPub"], device["kemPub"], requested)
    parsed = parse_pairing_qr(qr)
    granted = {"ops": ["read", "list"], "collections": ["notes"], "paths": ["notes/**", "!notes/_members"]}
    bundle = assemble_pairing_bundle(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        parsed,
        {},
        AssemblePairingBundleOpts(granted_scope=granted),
    )
    assert bundle.cap_cert["scope"] == granted
    assert "*" not in bundle.cap_cert["scope"]["collections"]


def test_assemble_fails_closed_without_granted_scope() -> None:
    root = derive_root_identity("alice-root-passphrase")
    device = _new_device()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], V["qrPayload"]["object"]["requestedScope"])
    parsed = parse_pairing_qr(qr)
    with pytest.raises(ValueError, match="granted_scope"):
        assemble_pairing_bundle(
            {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub}, parsed, {}
        )


def test_install_binds_bundle_to_qr_nonce() -> None:
    root = derive_root_identity("alice-root-passphrase")
    device = _new_device()
    qr_nonce = b"\x11" * 16
    qr = build_pairing_qr(
        device["edPub"], device["kemPub"], V["qrPayload"]["object"]["requestedScope"], qr_nonce=qr_nonce
    )
    parsed = parse_pairing_qr(qr)
    bundle = assemble_pairing_bundle(
        {"edPriv": root.keys.ed_priv, "edPub": root.keys.ed_pub},
        parsed,
        {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    assert bundle.qr_nonce == parsed.qr_nonce
    now = bundle.cap_cert["nbf"] + 5
    other_nonce = base64.b64encode(b"\x22" * 16).decode("ascii")
    with pytest.raises(ValueError, match="qrNonce"):
        install_pairing_bundle(bundle, device, now=now, expected_qr_nonce=other_nonce)
    ok = install_pairing_bundle(bundle, device, now=now, expected_qr_nonce=parsed.qr_nonce)
    assert ok.credentials.device["edPub"] == device["edPub"]


def test_install_rejects_unexpected_root_when_pinned() -> None:
    root = derive_root_identity("alice-root-passphrase")
    attacker = derive_root_identity("attacker-root-passphrase")
    device = _new_device()
    qr = build_pairing_qr(device["edPub"], device["kemPub"], V["qrPayload"]["object"]["requestedScope"])
    parsed = parse_pairing_qr(qr)
    # The attacker's OWN root assembles a validly-signed bundle for this device
    # (e.g. answering an open rendezvous), trying to enroll it into its account.
    bundle = assemble_pairing_bundle(
        {"edPriv": attacker.keys.ed_priv, "edPub": attacker.keys.ed_pub},
        parsed,
        {},
        AssemblePairingBundleOpts(granted_scope=parsed.requested_scope),
    )
    now = bundle.cap_cert["nbf"] + 5
    # Pinning the real root rejects the attacker's bundle.
    with pytest.raises(ValueError, match="root identity"):
        install_pairing_bundle(bundle, device, now=now, expected_root_ed_pub=root.keys.ed_pub)
    # Pinning the actual issuer (or omitting the pin) installs.
    ok = install_pairing_bundle(bundle, device, now=now, expected_root_ed_pub=attacker.keys.ed_pub)
    assert ok.credentials.root_ed_pub == attacker.keys.ed_pub


# ── PBKDF2 + server-relay encryption ──────────────────────────────────────────


def test_derive_code_key_is_deterministic_and_32_bytes() -> None:
    salt = b"\x01\x02\x03\x04"
    a = derive_code_key("123456", salt)
    b = derive_code_key("123456", salt)
    assert a == b
    assert len(a) == 32


def test_derive_code_key_differs_for_different_codes() -> None:
    salt = b"\x01\x02\x03\x04"
    a = derive_code_key("123456", salt)
    b = derive_code_key("654321", salt)
    assert a != b


# Real keypair (from the vector) so the proof-of-possession signature verifies.
def _relay_device() -> dict[str, str]:
    nd = V["newDevice"]
    return {"edPriv": nd["edPriv"], "edPub": nd["edPub"], "kemPub": nd["kemPub"]}


def _relay_reencrypt(code: str, request_nonce_b64: str, payload: dict) -> "PairingRequestEncrypted":
    """Re-encrypt a (possibly tampered) payload under the code key, as a relay
    that has learned the code would."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import secrets as _secrets
    from starfish_identities.pairing import PairingRequestEncrypted

    nonce_bytes = base64.b64decode(request_nonce_b64)
    key = derive_code_key(code, nonce_bytes)
    iv = _secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(payload).encode("utf-8"), None)
    return PairingRequestEncrypted(
        v=1,
        request_nonce=request_nonce_b64,
        iv=base64.b64encode(iv).decode("ascii"),
        ct=base64.b64encode(ct).decode("ascii"),
    )


def _relay_decrypt(code: str, enc: "PairingRequestEncrypted") -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce_bytes = base64.b64decode(enc.request_nonce)
    key = derive_code_key(code, nonce_bytes)
    pt = AESGCM(key).decrypt(base64.b64decode(enc.iv), base64.b64decode(enc.ct), None)
    return json.loads(pt.decode("utf-8"))


def test_pairing_request_relay_roundtrip_recovers_pubkeys() -> None:
    device = _relay_device()
    nonce = bytes(i + 1 for i in range(16))
    enc = build_pairing_request(device, "123456", request_nonce=nonce)
    assert enc.v == 1
    assert enc.request_nonce == base64.b64encode(nonce).decode("ascii")
    recovered = read_pairing_request(enc, "123456")
    assert recovered == {"devEdPub": device["edPub"], "devKemPub": device["kemPub"]}


def test_pairing_request_fails_with_wrong_code() -> None:
    device = _relay_device()
    enc = build_pairing_request(device, "123456", request_nonce=bytes(16))
    with pytest.raises(ValueError):
        read_pairing_request(enc, "000000")


def test_pairing_request_rejects_substituted_kem_pub_pop_mismatch() -> None:
    device = _relay_device()
    code = "123456"
    enc = build_pairing_request(device, code)
    # Relay knows the code: decrypt, swap devKemPub for an attacker KEM key,
    # keep the original popSig, re-encrypt under the same code+nonce.
    payload = _relay_decrypt(code, enc)
    payload["devKemPub"] = "cc" * 32
    tampered = _relay_reencrypt(code, enc.request_nonce, payload)
    with pytest.raises(ValueError, match="proof-of-possession"):
        read_pairing_request(tampered, code)


def test_pairing_request_rejects_missing_pop_sig() -> None:
    device = _relay_device()
    code = "123456"
    enc = build_pairing_request(device, code)
    payload = _relay_decrypt(code, enc)
    del payload["popSig"]
    stripped = _relay_reencrypt(code, enc.request_nonce, payload)
    with pytest.raises(ValueError, match="proof-of-possession"):
        read_pairing_request(stripped, code)


def test_derive_code_key_default_is_owasp_600k() -> None:
    salt = bytes([9]) * 16
    default = derive_code_key("123456", salt)
    at_600k = derive_code_key("123456", salt, 600_000)
    at_200k = derive_code_key("123456", salt, 200_000)
    assert default == at_600k
    assert default != at_200k


def test_pairing_response_roundtrip_through_relay() -> None:
    nonce = bytes(7 for _ in range(16))
    request_nonce_b64 = base64.b64encode(nonce).decode("ascii")
    enc = build_pairing_response(PairingBundle.from_dict(V["bundle"]), "987654", request_nonce_b64)
    assert enc.v == 1
    assert enc.request_nonce == request_nonce_b64
    bundle = read_pairing_response(enc, "987654")
    assert bundle.to_dict() == V["bundle"]
