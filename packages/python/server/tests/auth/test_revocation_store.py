"""Tests for the in-memory cap-cert revocation store."""

import base64
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.revocation import revocation_list_canonical_signing_input
from starfish_server.auth.revocation_store import (
    REVOCATION_RETAIN_SKEW_SEC,
    RevocationEntry,
    RevocationList,
    create_in_memory_revocation_store,
    revocation_retain_until_sec,
)


def _keypair(seed_byte: int) -> tuple[Ed25519PrivateKey, str, str]:
    """Return (priv, pub_hex, user_id) for a deterministic seed byte."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    pub = priv.public_key()
    from cryptography.hazmat.primitives import serialization

    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = pub_bytes.hex()
    user_id = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return priv, pub_hex, user_id


def _sign_list(unsigned: dict, priv: Ed25519PrivateKey) -> RevocationList:
    canonical = revocation_list_canonical_signing_input(unsigned).encode("utf-8")
    sig = priv.sign(canonical)
    return {**unsigned, "sig": base64.b64encode(sig).decode("ascii")}  # type: ignore[return-value]


def test_revocation_retain_until_includes_clock_skew() -> None:
    entry: RevocationEntry = {"sub": "s", "nonce": "n", "exp": 1_000}
    assert REVOCATION_RETAIN_SKEW_SEC == 300
    assert revocation_retain_until_sec(entry) == 1_300
    assert revocation_retain_until_sec(entry, 0) == 1_000


def test_store_keeps_cap_revoked_past_exp() -> None:
    # The resolver still accepts a cap until exp + skew, so an entry must
    # outlive exp. The in-memory store is generation-based and never time-
    # prunes, so is_revoked stays true regardless of how far past exp we are.
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()
    exp = 1_000
    entry: RevocationEntry = {"sub": "leaked", "nonce": "leaked-n", "exp": exp}
    list_signed = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 1,
            "revoked": [entry],
        },
        alice_priv,
    )
    assert store.accept_list(list_signed)["ok"] is True
    assert store.is_revoked(alice_pub, "leaked", "leaked-n") is True
    assert revocation_retain_until_sec(entry) > exp


def test_subject_level_revoke_invalidates_every_nonce() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x77)
    store = create_in_memory_revocation_store()
    list_signed = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 1,
            "revoked": [],
            "revokedSubjects": [{"sub": "device-sub", "exp": 9999999999}],
        },
        alice_priv,
    )
    assert store.accept_list(list_signed)["ok"] is True
    # A nonce never named individually is still revoked — what a re-minted cap
    # (fresh nonce) on a compromised device would carry.
    assert store.is_revoked(alice_pub, "device-sub", "fresh-nonce") is True
    assert store.is_revoked(alice_pub, "device-sub", "another-nonce") is True
    # A different subject is unaffected.
    assert store.is_revoked(alice_pub, "other-sub", "fresh-nonce") is False


def test_higher_generation_lifts_subject_level_revoke() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x78)
    store = create_in_memory_revocation_store()
    store.accept_list(
        _sign_list(
            {
                "v": 1, "iss": alice_pub, "issUserId": alice_uid, "generation": 1,
                "revoked": [], "revokedSubjects": [{"sub": "device-sub", "exp": 9999999999}],
            },
            alice_priv,
        )
    )
    assert store.is_revoked(alice_pub, "device-sub", "n") is True
    # Generation 2 omits the subject — the new list is authoritative.
    store.accept_list(
        _sign_list(
            {"v": 1, "iss": alice_pub, "issUserId": alice_uid, "generation": 2, "revoked": []},
            alice_priv,
        )
    )
    assert store.is_revoked(alice_pub, "device-sub", "n") is False


def test_accept_signed_list_and_lookup() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()
    entry: RevocationEntry = {"sub": "sub-1", "nonce": "nonce-1", "exp": 9999999999}
    unsigned = {
        "v": 1,
        "iss": alice_pub,
        "issUserId": alice_uid,
        "generation": 1,
        "revoked": [entry],
    }
    list_signed = _sign_list(unsigned, alice_priv)
    result = store.accept_list(list_signed)
    assert result["ok"] is True
    assert store.is_revoked(alice_pub, "sub-1", "nonce-1") is True
    assert store.is_revoked(alice_pub, "sub-1", "other") is False
    assert store.is_revoked(alice_pub, "other", "nonce-1") is False


def test_accepts_generation_zero_as_first_list() -> None:
    # The monotonicity gate rejects a generation <= the current one, but the very
    # first list has no current generation, so generation 0 is a valid starting
    # point (and a generation-0 replay is then rejected). Mirrors revocation-store.test.ts.
    alice_priv, alice_pub, alice_uid = _keypair(0x43)
    store = create_in_memory_revocation_store()
    entry: RevocationEntry = {"sub": "sub-z", "nonce": "nonce-z", "exp": 9999999999}
    gen0 = _sign_list(
        {"v": 1, "iss": alice_pub, "issUserId": alice_uid, "generation": 0, "revoked": [entry]},
        alice_priv,
    )
    assert store.accept_list(gen0)["ok"] is True
    assert store.is_revoked(alice_pub, "sub-z", "nonce-z") is True
    # A second generation-0 list is now stale (not strictly greater).
    assert store.accept_list(gen0)["ok"] is False


def test_reject_forged_signature() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    _, _, _ = _keypair(0x99)
    bob_priv, _, _ = _keypair(0x99)
    store = create_in_memory_revocation_store()
    unsigned = {
        "v": 1,
        "iss": alice_pub,
        "issUserId": alice_uid,
        "generation": 1,
        "revoked": [{"sub": "x", "nonce": "y", "exp": 100}],
    }
    list_signed = _sign_list(unsigned, bob_priv)
    result = store.accept_list(list_signed)
    assert result["ok"] is False
    assert store.is_revoked(alice_pub, "x", "y") is False


def test_reject_lower_or_equal_generation() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()

    list1 = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 5,
            "revoked": [{"sub": "sub-1", "nonce": "n1", "exp": 100}],
        },
        alice_priv,
    )
    assert store.accept_list(list1)["ok"] is True

    list_same = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 5,
            "revoked": [],
        },
        alice_priv,
    )
    assert store.accept_list(list_same)["ok"] is False

    list_lower = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 4,
            "revoked": [],
        },
        alice_priv,
    )
    assert store.accept_list(list_lower)["ok"] is False
    # Original still in effect
    assert store.is_revoked(alice_pub, "sub-1", "n1") is True


def test_higher_generation_replaces_list() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()
    list1 = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 1,
            "revoked": [{"sub": "old-sub", "nonce": "old-nonce", "exp": 100}],
        },
        alice_priv,
    )
    assert store.accept_list(list1)["ok"] is True
    assert store.is_revoked(alice_pub, "old-sub", "old-nonce") is True

    list2 = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 2,
            "revoked": [{"sub": "new-sub", "nonce": "new-nonce", "exp": 100}],
        },
        alice_priv,
    )
    assert store.accept_list(list2)["ok"] is True
    assert store.is_revoked(alice_pub, "old-sub", "old-nonce") is False
    assert store.is_revoked(alice_pub, "new-sub", "new-nonce") is True


def test_unknown_issuer_returns_false() -> None:
    store = create_in_memory_revocation_store()
    assert store.is_revoked("nope", "x", "y") is False


# --- O(1) lookup + max_issuers cap ---


def test_is_revoked_is_fast_for_large_lists() -> None:
    import time as _time

    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()
    revoked = [
        {"sub": f"sub-{i}", "nonce": f"nonce-{i}", "exp": 9_999_999_999}
        for i in range(5000)
    ]
    list_signed = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 1,
            "revoked": revoked,
        },
        alice_priv,
    )
    assert store.accept_list(list_signed)["ok"] is True
    start = _time.perf_counter()
    for _ in range(100):
        store.is_revoked(alice_pub, "sub-4999", "nonce-4999")
        store.is_revoked(alice_pub, "sub-0", "nonce-0")
        store.is_revoked(alice_pub, "sub-x", "nonce-x")
    elapsed = _time.perf_counter() - start
    # 300 lookups against a 5000-entry list. With O(1) this completes in
    # under 50ms even on a cold CPython 3.14 interpreter; with the linear
    # scan it would take 100s of ms.
    assert elapsed < 0.05, f"isRevoked too slow: {elapsed*1000:.1f}ms"


def test_index_rebuilt_when_higher_generation_replaces_list() -> None:
    alice_priv, alice_pub, alice_uid = _keypair(0x42)
    store = create_in_memory_revocation_store()
    l1 = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 1,
            "revoked": [{"sub": "old", "nonce": "n", "exp": 100}],
        },
        alice_priv,
    )
    assert store.accept_list(l1)["ok"] is True
    assert store.is_revoked(alice_pub, "old", "n") is True

    l2 = _sign_list(
        {
            "v": 1,
            "iss": alice_pub,
            "issUserId": alice_uid,
            "generation": 2,
            "revoked": [{"sub": "new", "nonce": "n2", "exp": 100}],
        },
        alice_priv,
    )
    assert store.accept_list(l2)["ok"] is True
    assert store.is_revoked(alice_pub, "old", "n") is False
    assert store.is_revoked(alice_pub, "new", "n2") is True


def test_rejects_new_issuers_beyond_max_issuers() -> None:
    a_priv, a_pub, a_uid = _keypair(0x10)
    b_priv, b_pub, b_uid = _keypair(0x20)
    c_priv, c_pub, c_uid = _keypair(0x30)
    store = create_in_memory_revocation_store(max_issuers=2)

    def mk(priv, pub, uid):
        return _sign_list(
            {
                "v": 1,
                "iss": pub,
                "issUserId": uid,
                "generation": 1,
                "revoked": [],
            },
            priv,
        )

    assert store.accept_list(mk(a_priv, a_pub, a_uid))["ok"] is True
    assert store.accept_list(mk(b_priv, b_pub, b_uid))["ok"] is True
    third = store.accept_list(mk(c_priv, c_pub, c_uid))
    assert third["ok"] is False
    assert third["reason"] == "too-many-issuers"


def test_allows_updates_to_known_issuer_at_cap() -> None:
    a_priv, a_pub, a_uid = _keypair(0x10)
    b_priv, b_pub, b_uid = _keypair(0x20)
    store = create_in_memory_revocation_store(max_issuers=2)

    def mk(priv, pub, uid, gen):
        return _sign_list(
            {
                "v": 1,
                "iss": pub,
                "issUserId": uid,
                "generation": gen,
                "revoked": [{"sub": f"g-{gen}", "nonce": "n", "exp": 1}],
            },
            priv,
        )

    assert store.accept_list(mk(a_priv, a_pub, a_uid, 1))["ok"] is True
    assert store.accept_list(mk(b_priv, b_pub, b_uid, 1))["ok"] is True
    # Updating an existing issuer at the cap should still work.
    assert store.accept_list(mk(a_priv, a_pub, a_uid, 2))["ok"] is True
    assert store.is_revoked(a_pub, "g-2", "n") is True
