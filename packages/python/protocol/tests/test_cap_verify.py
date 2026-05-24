"""Tests for cap-cert signature and well-formedness verification."""

import copy
import json
import pathlib

import pytest

from starfish_protocol.cap import (
    assert_cap_cert_well_formed,
    path_glob_match,
    sign_cap_cert,
    verify_cap_cert,
    verify_cap_cert_signature,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "cap-cert.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())

# Alice's root edPriv = derive_root_identity("alice-root-passphrase").keys.ed_priv.
# Hardcoded here to keep starfish_protocol dependency-free (no SDK dep).
# Ed25519 is deterministic, so re-signing the vector's canonical input with
# this priv yields the vector's sig byte-for-byte.
ALICE_ED_PRIV = "ad5a91be445615ad20823ff607df3d69f9fabc7a2f3f6cfce79dd6b8827e1a89"


def test_verify_signature_device_cap() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    assert verify_cap_cert_signature(cert) is True


def test_verify_signature_member_cap() -> None:
    cert = VECTORS["memberCap"]["cert"]
    assert verify_cap_cert_signature(cert) is True


def test_verify_signature_rejects_forged_device_cap() -> None:
    cert = VECTORS["forgedDeviceCap"]["cert"]
    assert verify_cap_cert_signature(cert) is False


def test_verify_signature_cross_suite_member_cap() -> None:
    # The cap `sig` is Ed25519 (issAlg) even though the subject suite is
    # secp256k1 — the non-default subAlg is folded into the signed bytes.
    cert = VECTORS["crossSuiteMemberCap"]["cert"]
    assert verify_cap_cert_signature(cert) is True


def test_verify_signature_mixed_kem_member_cap() -> None:
    cert = VECTORS["mixedKemMemberCap"]["cert"]
    assert verify_cap_cert_signature(cert) is True


def test_verify_signature_rejects_stripped_sub_alg() -> None:
    # Cross-suite cert's ed25519 signature with the signed subAlg tag stripped →
    # canonical input differs → verification fails. Cross-language downgrade
    # canary (mirrors cap-verify.test.ts).
    case = VECTORS["strippedSubAlgMemberCap"]
    assert case["expectVerify"] is False
    assert verify_cap_cert_signature(case["cert"]) is False


def test_verify_signature_rejects_swapped_sub_alg() -> None:
    case = VECTORS["swappedSubAlgMemberCap"]
    assert case["expectVerify"] is False
    assert verify_cap_cert_signature(case["cert"]) is False


def test_well_formed_accepts_cross_suite_member_cap() -> None:
    # secp256k1 subject omits subKem (reuses sign key for KEM); the predicate
    # must accept it. Mirrors cap-verify.test.ts.
    assert_cap_cert_well_formed(VECTORS["crossSuiteMemberCap"]["cert"])


def test_well_formed_accepts_mixed_kem_member_cap() -> None:
    # subAlg=secp256k1 but subKemAlg=ed25519 → a distinct X25519 subKem present.
    assert_cap_cert_well_formed(VECTORS["mixedKemMemberCap"]["cert"])


def test_verify_cap_cert_ok_for_device_cap_in_window() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    result = verify_cap_cert(cert, now=cert["nbf"] + 100)
    assert result["ok"] is True


def test_verify_cap_cert_ok_for_member_cap_in_window() -> None:
    # The pinned vector pre-dates the ``member-keyring-not-denied`` and
    # ``member-members-not-denied`` rules; patch the cert in-memory and
    # re-sign so the orchestrator passes every check.
    base = VECTORS["memberCap"]["cert"]
    unsigned = {k: v for k, v in base.items() if k != "sig"}
    unsigned["scope"] = {
        **unsigned["scope"],
        "paths": [
            "shared-notes/*",
            "!shared-notes/_keyring",
            "!shared-notes/_members",
        ],
    }
    cert = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    result = verify_cap_cert(cert, now=cert["nbf"] + 100)
    assert result["ok"] is True


def test_verify_cap_cert_rejects_forged() -> None:
    cert = VECTORS["forgedDeviceCap"]["cert"]
    result = verify_cap_cert(cert, now=cert["nbf"] + 100)
    assert result["ok"] is False


def test_verify_cap_cert_not_yet_valid() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    result = verify_cap_cert(cert, now=cert["nbf"] - 1000, clock_skew_sec=0)
    assert result["ok"] is False
    assert "reason" in result


def test_verify_cap_cert_expired() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    result = verify_cap_cert(cert, now=cert["exp"] + 1000, clock_skew_sec=0)
    assert result["ok"] is False
    assert "reason" in result


def test_verify_cap_cert_honors_clock_skew() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    # 60s before nbf with default 300s skew → still ok
    result = verify_cap_cert(cert, now=cert["nbf"] - 60)
    assert result["ok"] is True


def test_verify_at_exact_expiry_skew_boundary_is_inclusive() -> None:
    # The expiry gate is ``now > exp + skew`` (strict), so the instant exactly
    # at ``exp + skew`` is still valid and one second past it expires. Pins the
    # off-by-one so a future ``>=`` rewrite (which would reject the boundary
    # second) can't slip through — and so it matches the TS comparator.
    cert = VECTORS["deviceCap"]["cert"]
    skew = 300
    at_boundary = verify_cap_cert(cert, now=cert["exp"] + skew, clock_skew_sec=skew)
    assert at_boundary["ok"] is True
    just_past = verify_cap_cert(cert, now=cert["exp"] + skew + 1, clock_skew_sec=skew)
    assert just_past["ok"] is False
    assert just_past["reason"] == "expired"


def test_verify_at_exact_not_before_skew_boundary_is_inclusive() -> None:
    # Symmetric lower edge: ``now < nbf - skew`` (strict) means the instant
    # exactly at ``nbf - skew`` is already valid and one second earlier is
    # not-yet-valid.
    cert = VECTORS["deviceCap"]["cert"]
    skew = 300
    at_boundary = verify_cap_cert(cert, now=cert["nbf"] - skew, clock_skew_sec=skew)
    assert at_boundary["ok"] is True
    just_before = verify_cap_cert(cert, now=cert["nbf"] - skew - 1, clock_skew_sec=skew)
    assert just_before["ok"] is False
    assert just_before["reason"] == "not-yet-valid"


def test_sign_cap_cert_reproduces_vector_signature() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    signed = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    assert signed["sig"] == VECTORS["deviceCap"]["signatureBase64"]


def test_sign_cap_cert_round_trips() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    unsigned = {k: v for k, v in cert.items() if k != "sig"}
    signed = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    assert verify_cap_cert_signature(signed) is True


def test_assert_well_formed_accepts_device_vector() -> None:
    assert_cap_cert_well_formed(VECTORS["deviceCap"]["cert"])


# Member-specific shape rules (member-self / member-private-path /
# member-members-not-denied / member-keyring-not-denied / …) moved to
# ``assert_member_cap_shape`` in ``starfish_sharing``; their tests live
# there. The protocol's ``assert_cap_cert_well_formed`` now only enforces
# the generic iss/sub-userId relations.


def test_assert_well_formed_accepts_member_vector_generic_only() -> None:
    # Pinned vector lacks `_members`/`_keyring` denies — protocol no longer
    # rejects this; the sharing plugin owns that rule now.
    assert_cap_cert_well_formed(copy.deepcopy(VECTORS["memberCap"]["cert"]))


def test_assert_well_formed_read_only_member_with_members_deny_ok() -> None:
    ok = copy.deepcopy(VECTORS["memberCap"]["cert"])
    ok["scope"]["ops"] = ["read", "list"]
    ok["scope"]["paths"] = ["shared-notes/*", "!shared-notes/_members"]
    assert_cap_cert_well_formed(ok)


def test_assert_well_formed_no_members_deny_required_when_no_matching_allow() -> None:
    # A scope that only allows a specific subpath cannot reach `_members`,
    # so no deny is required (parallel to the keyring rule's behavior).
    ok = copy.deepcopy(VECTORS["memberCap"]["cert"])
    ok["scope"]["ops"] = ["read", "list"]
    ok["scope"]["paths"] = ["shared-notes/public/*"]
    assert_cap_cert_well_formed(ok)


def test_assert_well_formed_iss_userid_mismatch() -> None:
    bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    bad["issUserId"] = "0000000000000000"
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "iss-userid-mismatch"


def test_assert_well_formed_sub_userid_mismatch() -> None:
    bad = copy.deepcopy(VECTORS["memberCap"]["cert"])
    bad["subUserId"] = "0000000000000000"
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "sub-userid-mismatch"


def test_assert_well_formed_rejects_explicit_null_sub_userid() -> None:
    # An explicit ``subUserId: null`` is *present* and must be rejected as
    # malformed (PRESENCE test, matching TS ``c.subUserId !== undefined`` →
    # ``typeof null !== "string"``). ``is not None`` would treat null as "no
    # binding" and silently skip the hash check — a cross-language split.
    bad = copy.deepcopy(VECTORS["memberCap"]["cert"])
    bad["subUserId"] = None
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_does_not_enforce_member_rules() -> None:
    # A member cap with `*` collections + a private-namespace path used to
    # raise here; the protocol layer is now kind-agnostic and accepts it.
    # ``assert_member_cap_shape`` (starfish_sharing) is the authoritative owner.
    ok = copy.deepcopy(VECTORS["memberCap"]["cert"])
    ok["scope"]["collections"] = ["*"]
    ok["scope"]["paths"] = ["users/{identity}/private"]
    assert_cap_cert_well_formed(ok)


def test_assert_well_formed_accepts_device_without_sub_userid() -> None:
    cert = VECTORS["deviceCap"]["cert"]
    assert "subUserId" not in cert
    assert_cap_cert_well_formed(cert)


def test_verify_rejects_validly_signed_cert_with_string_scope_ops() -> None:
    base = VECTORS["deviceCap"]["cert"]
    # scope.ops is a string, not a list. Without shape validation the resolver
    # would iterate it character-by-character into fabricated roles.
    malformed = {k: v for k, v in base.items() if k != "sig"}
    malformed["scope"] = {"ops": "read", "collections": ["notes"]}
    signed = sign_cap_cert(malformed, ALICE_ED_PRIV)
    # The signature is valid over the malformed bytes — only the structural
    # check stands between this cert and role synthesis.
    assert verify_cap_cert_signature(signed) is True
    result = verify_cap_cert(signed, now=base["nbf"] + 100)
    assert result["ok"] is False
    assert result["reason"] == "malformed-shape"


def test_assert_well_formed_raises_malformed_shape_for_string_ops() -> None:
    bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    bad["scope"]["ops"] = "read"
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_raises_malformed_shape_for_unknown_op() -> None:
    bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    bad["scope"]["ops"] = ["read", "admin"]
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_raises_malformed_shape_for_missing_scope() -> None:
    bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    del bad["scope"]
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_raises_malformed_shape_for_unknown_kind() -> None:
    bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    bad["kind"] = "root"
    with pytest.raises(ValueError) as exc:
        assert_cap_cert_well_formed(bad)
    assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_rejects_non_integer_exp() -> None:
    # A wire `exp: 1e400` parses to inf; it must not pass the expiry gate.
    for bad_exp in (float("inf"), float("-inf"), float("nan"), 1.5):
        bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
        bad["exp"] = bad_exp
        with pytest.raises(ValueError) as exc:
            assert_cap_cert_well_formed(bad)
        assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_accepts_whole_number_float_nbf_exp() -> None:
    # A cap-cert serialized with a trailing `.0` arrives as a Python float. It
    # must be accepted (it was rejected before) so the cert authenticates
    # identically on a TS server, which cannot distinguish `1700000000.0` from
    # the integer after JSON parsing.
    ok = copy.deepcopy(VECTORS["deviceCap"]["cert"])
    ok["nbf"] = float(ok["nbf"])
    ok["exp"] = float(ok["exp"])
    assert_cap_cert_well_formed(ok)


def test_assert_well_formed_rejects_bad_nonce() -> None:
    # The nonce must be standard base64 of exactly 16 bytes; a degenerate or
    # reused nonce weakens per-cap revocation (which keys on the nonce).
    for bad_nonce in ("", "n", "PLACEHOLDER", "AAAA", "not base64!!"):
        bad = copy.deepcopy(VECTORS["deviceCap"]["cert"])
        bad["nonce"] = bad_nonce
        with pytest.raises(ValueError) as exc:
            assert_cap_cert_well_formed(bad)
        assert exc.value.args[0] == "malformed-shape"


def test_assert_well_formed_accepts_valid_nonce() -> None:
    assert_cap_cert_well_formed(copy.deepcopy(VECTORS["deviceCap"]["cert"]))


# ── Scope / validity-window structural edges ──────────────────────────────────


def test_empty_ops_list_is_well_formed_and_verifies() -> None:
    # An empty ops list passes the vacuous membership check and verify reports
    # ok — but the resolver synthesizes no roles from zero ops, so the cap
    # authorizes nothing. Pin that an empty scope is structurally valid (it must
    # not raise) rather than silently rejected or, worse, treated as wildcard.
    base = VECTORS["deviceCap"]["cert"]
    unsigned = {k: v for k, v in base.items() if k != "sig"}
    unsigned["scope"] = {**unsigned["scope"], "ops": []}
    signed = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    assert_cap_cert_well_formed(signed)  # does not raise
    result = verify_cap_cert(signed, now=base["nbf"] + 100)
    assert result["ok"] is True
    assert signed["scope"]["ops"] == []


def test_inverted_validity_window_is_rejected_with_reason_inverted_window() -> None:
    # ``exp`` set BEFORE ``nbf``. Without an explicit ``exp > nbf`` check, the
    # instant where the skew margins overlap (``nbf - exp <= 2*skew``) would clear
    # both time gates — so the verifier rejects ``exp <= nbf`` up front, even at a
    # ``now`` that sits inside that overlap. Pins the hardening.
    base = VECTORS["deviceCap"]["cert"]
    unsigned = {k: v for k, v in base.items() if k != "sig"}
    nbf = unsigned["nbf"]
    unsigned["exp"] = nbf - 100  # 100s before nbf
    signed = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    result = verify_cap_cert(signed, now=nbf, clock_skew_sec=300)
    assert result["ok"] is False
    assert result["reason"] == "inverted-window"


def test_zero_width_validity_window_is_rejected() -> None:
    # ``exp == nbf`` is also rejected — the window must be strictly positive.
    base = VECTORS["deviceCap"]["cert"]
    unsigned = {k: v for k, v in base.items() if k != "sig"}
    unsigned["exp"] = unsigned["nbf"]
    signed = sign_cap_cert(unsigned, ALICE_ED_PRIV)
    result = verify_cap_cert(signed, now=unsigned["nbf"], clock_skew_sec=300)
    assert result["ok"] is False
    assert result["reason"] == "inverted-window"


# ── path_glob_match: the scope-barrier matcher (no prior direct unit test) ─────


def test_path_glob_single_star_does_not_cross_a_slash() -> None:
    assert path_glob_match("notes/*", "notes/a") is True
    assert path_glob_match("notes/*", "notes/a/b") is False


def test_path_glob_double_star_crosses_slashes() -> None:
    # ``**`` must reach across path segments — the member-cap ``!col/_keyring``
    # deny relies on it, so a matcher that stopped at a slash would clear a cap
    # the resolver later grants.
    assert path_glob_match("notes/**", "notes/a/b/c") is True
    assert path_glob_match("**/_keyring", "notes/sub/_keyring") is True


def test_path_glob_escapes_regex_specials_so_a_dot_is_literal() -> None:
    # A literal '.' in a collection/path name matches only '.', never any
    # character — otherwise 'a.b' would match 'axb' and a crafted collection
    # name could widen a scope barrier.
    assert path_glob_match("a.b", "a.b") is True
    assert path_glob_match("a.b", "axb") is False


def test_path_glob_requires_a_full_match_not_a_prefix() -> None:
    assert path_glob_match("notes", "notes/extra") is False
    assert path_glob_match("notes/*", "other/x") is False
