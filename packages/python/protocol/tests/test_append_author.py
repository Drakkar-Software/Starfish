"""Tests for v3.0 append-author Ed25519 signing.

Cross-language vector: tests/test-vectors/append-author.json. Ed25519 is
deterministic, so the signature is reproducible byte-for-byte across TS and
Python — these tests re-sign the vector data and assert the locked signature.
The signature binds the author to BOTH the data AND the documentKey.
"""

import json
import pathlib

import pytest

from starfish_protocol.append_author import (
    APPEND_AUTHOR_DOMAIN,
    append_author_canonical_input,
    sign_append_author,
    verify_append_author,
    verify_doc_author,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "append-author.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())
_SIGNER = VECTORS["signer"]
_WRONG_PUB = VECTORS["wrongSignerPub"]["edPub"]
_CASES = VECTORS["cases"]
_IDS = [c["label"] for c in _CASES]


def test_domain_tag_matches_vector() -> None:
    assert APPEND_AUTHOR_DOMAIN == VECTORS["domain"]


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_canonical_input_matches_vector(case: dict) -> None:
    assert (
        append_author_canonical_input(case["documentKey"], case["data"])
        == case["canonicalSigningInput"]
    )


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_sign_reproduces_locked_signature(case: dict) -> None:
    out = sign_append_author(
        case["documentKey"], case["data"], _SIGNER["edPub"], _SIGNER["edPriv"], case["alg"]
    )
    assert out["authorPubkey"] == _SIGNER["edPub"]
    assert out["authorSignature"] == case["authorSignature"]


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_verifies_locked_signature(case: dict) -> None:
    assert (
        verify_append_author(
            case["documentKey"], case["data"], _SIGNER["edPub"], case["authorSignature"], case["alg"]
        )
        is case["expectVerify"]
    )


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_rejects_wrong_signer(case: dict) -> None:
    assert (
        verify_append_author(
            case["documentKey"], case["data"], _WRONG_PUB, case["authorSignature"], case["alg"]
        )
        is False
    )


@pytest.mark.parametrize("case", _CASES, ids=_IDS)
def test_rejects_different_document_key(case: dict) -> None:
    # Path binding: the same signature must not verify under another document key.
    assert (
        verify_append_author(
            case["documentKey"] + "/elsewhere",
            case["data"],
            _SIGNER["edPub"],
            case["authorSignature"],
            case["alg"],
        )
        is False
    )


def test_rejects_tampered_data() -> None:
    case = _CASES[0]
    tampered = {**case["data"], "authorId": "evil"}
    assert (
        verify_append_author(
            case["documentKey"], tampered, _SIGNER["edPub"], case["authorSignature"], case["alg"]
        )
        is False
    )


def test_returns_false_never_raises_on_malformed_inputs() -> None:
    case = _CASES[0]
    dk = case["documentKey"]
    assert verify_append_author(dk, case["data"], _SIGNER["edPub"], "not base64 !!!", case["alg"]) is False
    assert verify_append_author(dk, case["data"], "zz", case["authorSignature"], case["alg"]) is False


def test_signature_independent_of_data_key_order() -> None:
    # stable_stringify sorts keys, so a reordered-but-equal object signs identically.
    a = sign_append_author(
        "events",
        {"authorId": "abc", "text": "hello", "ts": 1747000000000},
        _SIGNER["edPub"],
        _SIGNER["edPriv"],
    )
    b = sign_append_author(
        "events",
        {"ts": 1747000000000, "text": "hello", "authorId": "abc"},
        _SIGNER["edPub"],
        _SIGNER["edPriv"],
    )
    assert a["authorSignature"] == b["authorSignature"]


def test_append_signature_does_not_verify_as_doc_signature() -> None:
    # Domain separation: an append-element signature must not verify as a
    # merge-document signature (different domain tag), even for the same inputs.
    case = _CASES[0]
    out = sign_append_author(case["documentKey"], case["data"], _SIGNER["edPub"], _SIGNER["edPriv"])
    assert (
        verify_doc_author(case["documentKey"], case["data"], _SIGNER["edPub"], out["authorSignature"])
        is False
    )
