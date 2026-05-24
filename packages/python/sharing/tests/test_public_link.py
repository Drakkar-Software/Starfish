"""Tests for the public-link API and audience cap minting.

Mirror of TS ``tests/public-link.test.ts``.
"""

from starfish_identities.identity import derive_root_identity
from starfish_protocol.cap import verify_cap_cert
from starfish_sharing import (
    AudienceMintOpts,
    create_public_link,
    mint_audience_cap,
    parse_public_link,
    redeem_public_link,
    scopes,
)


def _alice():
    return derive_root_identity("alice-root-passphrase")


def _bob():
    return derive_root_identity("bob-root-passphrase")


def _code_of(fn) -> str:
    try:
        fn()
        return "NO_THROW"
    except ValueError as e:
        return e.args[0] if e.args else "ValueError"


def test_open_link_round_trips_and_verifies() -> None:
    alice = _alice()
    link = create_public_link(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        nbf=1_747_000_000,
        ttl_sec=3600,
    )
    assert link.cap["kind"] == "audience"
    assert "aud" not in link.cap
    assert "sub" not in link.cap
    assert parse_public_link(link.fragment).cap == link.cap
    assert verify_cap_cert(link.cap, now=link.cap["nbf"] + 5)["ok"] is True


def test_restricted_link_aud_is_allowed_identities() -> None:
    alice = _alice()
    bob = _bob()
    link = create_public_link(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        allowed_identities=[bob.keys.ed_pub],
    )
    assert link.cap["aud"] == [bob.keys.ed_pub]
    assert parse_public_link(link.fragment).cap == link.cap


def test_redeem_sets_pub_header() -> None:
    alice = _alice()
    bob = _bob()
    link = create_public_link(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        allowed_identities=[bob.keys.ed_pub],
    )
    headers = redeem_public_link(
        parse_public_link(link.fragment),
        redeemer_ed_priv_hex=bob.keys.ed_priv,
        redeemer_ed_pub_hex=bob.keys.ed_pub,
        method="GET",
        path_and_query="/pull/broadcast/post-1",
        host="api.example.com",
    )
    assert headers["X-Starfish-Pub"] == bob.keys.ed_pub
    assert headers["Authorization"].startswith("Cap ")
    assert isinstance(headers["X-Starfish-Sig"], str)


def test_parse_rejects_malformed_fragment() -> None:
    assert _code_of(lambda: parse_public_link("!!!not-base64url!!!")) != "NO_THROW"


def test_rejects_empty_allowed_identities() -> None:
    alice = _alice()
    assert (
        _code_of(
            lambda: create_public_link(
                alice.keys.ed_priv,
                alice.keys.ed_pub,
                "broadcast",
                scopes.read_only("broadcast"),
                allowed_identities=[],
            )
        )
        == "audience-empty"
    )


def test_expires_at_wins_over_ttl() -> None:
    alice = _alice()
    cap = mint_audience_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(nbf=1_000_000, ttl_sec=10, expires_at=2_000_000),
    )
    assert cap["exp"] == 2_000_000


def test_rejects_expires_at_not_after_nbf() -> None:
    alice = _alice()
    assert (
        _code_of(
            lambda: mint_audience_cap(
                alice.keys.ed_priv,
                alice.keys.ed_pub,
                "broadcast",
                scopes.read_only("broadcast"),
                AudienceMintOpts(nbf=2_000_000, expires_at=1_000_000),
            )
        )
        == "expiresAt-not-after-nbf"
    )


def test_ttl_only_and_default() -> None:
    alice = _alice()
    with_ttl = mint_audience_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(nbf=1_000_000, ttl_sec=42),
    )
    assert with_ttl["exp"] == 1_000_042
    default = mint_audience_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        "broadcast",
        scopes.read_only("broadcast"),
        AudienceMintOpts(nbf=1_000_000),
    )
    assert default["exp"] == 1_000_000 + 30 * 24 * 3600


def test_shape_rejects_members_reach_without_deny() -> None:
    alice = _alice()
    assert (
        _code_of(
            lambda: mint_audience_cap(
                alice.keys.ed_priv,
                alice.keys.ed_pub,
                "broadcast",
                {"ops": ["read", "list"], "collections": ["broadcast"], "paths": ["broadcast/**"]},
            )
        )
        == "audience-members-not-denied"
    )


def test_shape_rejects_issuer_private_path() -> None:
    alice = _alice()
    assert (
        _code_of(
            lambda: mint_audience_cap(
                alice.keys.ed_priv,
                alice.keys.ed_pub,
                "broadcast",
                {
                    "ops": ["read", "list"],
                    "collections": ["broadcast"],
                    "paths": [f"users/{alice.user_id}/secret", "!broadcast/_members"],
                },
            )
        )
        == "audience-private-path"
    )
