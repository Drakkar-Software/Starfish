"""Tests for the ``audience`` (public-link) cap kind in the protocol layer.

Mirror of TS ``tests/audience-cap.test.ts``.
"""

import base64
import json
import pathlib

from starfish_protocol.cap import (
    assert_cap_cert_well_formed,
    cap_cert_canonical_signing_input,
    user_id_from_pub_hex,
    verify_cap_cert,
)

VECTORS = json.loads(
    (
        pathlib.Path(__file__).parent.parent.parent.parent.parent
        / "tests"
        / "test-vectors"
        / "cap-cert.json"
    ).read_text()
)

_ISS = "aa" * 32


def _code_of(fn) -> str:
    try:
        fn()
        return "NO_THROW"
    except ValueError as e:
        return e.args[0] if e.args else "ValueError"


def _base_audience(**overrides) -> dict:
    cert = {
        "v": 1,
        "kind": "audience",
        "iss": _ISS,
        "issUserId": user_id_from_pub_hex(_ISS),
        "scope": {"ops": ["read", "list"], "collections": ["broadcast"], "paths": ["broadcast/**"]},
        "nbf": 1000,
        "exp": 2000,
        "nonce": base64.b64encode(bytes([1]) * 16).decode("ascii"),
    }
    cert.update(overrides)
    return cert


def test_audience_vectors_canonical_and_verify() -> None:
    for name in ("audienceCapOpen", "audienceCapRestricted"):
        v = VECTORS[name]
        unsigned = {k: val for k, val in v["cert"].items() if k != "sig"}
        assert cap_cert_canonical_signing_input(unsigned) == v["canonicalSigningInput"]
        assert verify_cap_cert(v["cert"], now=v["cert"]["nbf"] + 5)["ok"] is True


def test_open_audience_cap_has_no_subject_or_aud_keys() -> None:
    c = VECTORS["audienceCapOpen"]["cert"]
    for k in ("sub", "subKem", "subUserId", "aud"):
        assert k not in c


def test_accepts_valid_open_and_restricted_audience() -> None:
    assert _code_of(lambda: assert_cap_cert_well_formed(_base_audience())) == "NO_THROW"
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=["bb" * 32]))) == "NO_THROW"
    )


def test_rejects_audience_with_sub_or_sub_kem() -> None:
    assert _code_of(lambda: assert_cap_cert_well_formed(_base_audience(sub="cc" * 32))) == "audience-has-sub"
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(subKem="cc" * 32)))
        == "audience-has-sub"
    )


def test_rejects_empty_aud() -> None:
    assert _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=[]))) == "audience-empty-aud"


def test_rejects_oversized_aud() -> None:
    aud = [format(i, "064x") for i in range(65)]
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=aud)))
        == "audience-aud-too-large"
    )


def test_rejects_bad_aud_entry() -> None:
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=["AB" * 32])))
        == "audience-aud-bad-entry"
    )
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=["ab"])))
        == "audience-aud-bad-entry"
    )


def test_rejects_duplicate_aud() -> None:
    dup = "bb" * 32
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=[dup, dup])))
        == "audience-aud-dup"
    )


def test_rejects_explicit_null_subject_on_audience() -> None:
    # A present `sub: null` (etc.) must be rejected exactly as TS rejects it
    # (`!== undefined`), not silently treated as absent — cross-language parity.
    assert _code_of(lambda: assert_cap_cert_well_formed(_base_audience(sub=None))) == "audience-has-sub"
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(subKem=None)))
        == "audience-has-sub"
    )
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(subUserId=None)))
        == "audience-has-sub"
    )


def test_rejects_explicit_null_aud_on_audience() -> None:
    # Present `aud: null` on an audience cap is a bad list, not "open".
    assert (
        _code_of(lambda: assert_cap_cert_well_formed(_base_audience(aud=None)))
        == "audience-aud-bad-entry"
    )


def test_rejects_member_with_aud() -> None:
    member = {
        "v": 1,
        "kind": "member",
        "iss": _ISS,
        "issUserId": user_id_from_pub_hex(_ISS),
        "sub": "dd" * 32,
        "subKem": "ee" * 32,
        "subUserId": user_id_from_pub_hex("dd" * 32),
        "scope": {"ops": ["read"], "collections": ["x"]},
        "nbf": 1000,
        "exp": 2000,
        "nonce": base64.b64encode(bytes([1]) * 16).decode("ascii"),
        "aud": ["bb" * 32],
    }
    assert _code_of(lambda: assert_cap_cert_well_formed(member)) == "non-audience-has-aud"
    # A present `aud: null` on a non-audience cap is also rejected (parity with TS).
    member_null = {**member, "aud": None}
    assert _code_of(lambda: assert_cap_cert_well_formed(member_null)) == "non-audience-has-aud"
