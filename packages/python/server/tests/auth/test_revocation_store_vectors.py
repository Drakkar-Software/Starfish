"""Cross-language vector tests for the v3.0 signed revocation list.

Vector source: ``tests/test-vectors/revocation-list.json``.

Coverage:
- ``gen1.list``: signature parses & verifies via the in-memory store's
  ``accept_list()`` accept path (which does Ed25519 verify internally).
- ``gen2.list``: accepted, supersedes gen1.
- ``forged.list``: rejected (``expectVerify: false``).
- The canonical signing input we reconstruct via
  ``stable_stringify(list \\ sig)`` matches ``vector.canonicalSigningInput``
  byte-for-byte.
"""

from __future__ import annotations

import json
import pathlib

from starfish_protocol.revocation import revocation_list_canonical_signing_input
from starfish_server.auth.revocation_store import (
    RevocationList,
    create_in_memory_revocation_store,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "revocation-list.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def _canonical_signing_input(list_signed: RevocationList) -> str:
    # Use the protocol's canonical function (which prepends the revocation-list
    # domain tag) so the reconstruction stays in lockstep with the signer.
    return revocation_list_canonical_signing_input(dict(list_signed))


def test_gen1_canonical_signing_input_matches_vector() -> None:
    gen1 = VECTORS["generations"]["1"]
    assert _canonical_signing_input(gen1["list"]) == gen1["canonicalSigningInput"]


def test_gen2_canonical_signing_input_matches_vector() -> None:
    gen2 = VECTORS["generations"]["2"]
    assert _canonical_signing_input(gen2["list"]) == gen2["canonicalSigningInput"]


def test_forged_canonical_signing_input_matches_gen2_body() -> None:
    forged = VECTORS["forged"]
    assert _canonical_signing_input(forged["list"]) == forged["canonicalSigningInput"]


def test_accept_gen1_list_signature_verifies() -> None:
    store = create_in_memory_revocation_store()
    result = store.accept_list(VECTORS["generations"]["1"]["list"])
    assert result["ok"] is True
    sub1 = VECTORS["subjects"]["alice_dev_1"]
    assert store.is_revoked(VECTORS["issuer"]["edPub"], sub1["edPub"], sub1["nonce"]) is True
    # alice_dev_2 not yet in gen1
    sub2 = VECTORS["subjects"]["alice_dev_2"]
    assert store.is_revoked(VECTORS["issuer"]["edPub"], sub2["edPub"], sub2["nonce"]) is False


def test_accept_gen2_supersedes_gen1() -> None:
    store = create_in_memory_revocation_store()
    assert store.accept_list(VECTORS["generations"]["1"]["list"])["ok"] is True
    assert store.accept_list(VECTORS["generations"]["2"]["list"])["ok"] is True
    sub1 = VECTORS["subjects"]["alice_dev_1"]
    sub2 = VECTORS["subjects"]["alice_dev_2"]
    iss = VECTORS["issuer"]["edPub"]
    assert store.is_revoked(iss, sub1["edPub"], sub1["nonce"]) is True
    assert store.is_revoked(iss, sub2["edPub"], sub2["nonce"]) is True


def test_reject_forged_list() -> None:
    store = create_in_memory_revocation_store()
    result = store.accept_list(VECTORS["forged"]["list"])
    assert result["ok"] is False
    assert result.get("reason") == "bad-signature"
    sub1 = VECTORS["subjects"]["alice_dev_1"]
    assert store.is_revoked(VECTORS["issuer"]["edPub"], sub1["edPub"], sub1["nonce"]) is False
