"""Tests for member cap-cert minting helpers."""

import pytest

from starfish_protocol.cap import verify_cap_cert
from starfish_identities.cap_mint import mint_device_cap
from starfish_identities.identity import derive_root_identity
from starfish_sharing.cap_mint import MintOpts, mint_member_cap, scopes


def test_mint_member_cap_returns_verifying_cert() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-notes",
        scopes.writer("shared-notes"),
    )
    assert cert["kind"] == "member"
    assert cert["subUserId"] == bob.user_id
    assert cert["scope"]["collections"] == ["shared-notes"]
    result = verify_cap_cert(cert, now=cert["nbf"] + 5)
    assert result["ok"] is True


def test_mint_allows_secp256k1_kem_now_wrappable() -> None:
    # The KEM phase relaxed the old mint gate: a non-ed25519 sub_kem_alg is now
    # mintable (the keyring wraps under any suite's ECDH).
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-notes",
        scopes.writer("shared-notes"),
        MintOpts(sub_kem_alg="secp256k1-schnorr"),
    )
    assert cert["subKemAlg"] == "secp256k1-schnorr"
    assert isinstance(cert["subKem"], str)
    assert verify_cap_cert(cert, now=cert["nbf"] + 5)["ok"] is True


def test_mint_allows_secp256k1_sign_with_x25519_kem() -> None:
    # The one usable decoupled combo today (key bytes are stand-ins).
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-notes",
        scopes.writer("shared-notes"),
        MintOpts(sub_alg="secp256k1-schnorr", sub_kem_alg="ed25519"),
    )
    assert cert["subAlg"] == "secp256k1-schnorr"
    assert cert["subKemAlg"] == "ed25519"
    assert isinstance(cert["subKem"], str)


def test_mint_member_cap_forces_collection_arg() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-notes",
        {
            "ops": ["read", "list", "write"],
            "paths": [
                "shared-notes/**",
                "!shared-notes/_keyring",
                "!shared-notes/_members",
            ],
            "collections": ["this-gets-overridden"],
        },
    )
    assert cert["scope"]["collections"] == ["shared-notes"]


def test_mint_member_cap_rejects_wildcard_collections() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "*",
            {
                "ops": ["read", "list"],
                "paths": ["shared-notes/*", "!shared-notes/_members"],
                "collections": ["*"],
            },
        )
    assert exc.value.args[0] == "member-wildcard-collections"


def test_mint_member_cap_rejects_private_path() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared-notes",
            {
                "ops": ["read", "write", "list"],
                "paths": ["users/{identity}/private"],
                "collections": ["shared-notes"],
            },
        )
    assert exc.value.args[0] == "member-private-path"


def test_mint_member_cap_rejects_self() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub, "userIdHex": alice.user_id},
            "shared-notes",
            scopes.writer("shared-notes"),
        )
    assert exc.value.args[0] == "member-self"


def test_mint_member_cap_rejects_members_not_denied() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {"ops": ["read", "list"], "paths": ["shared/*"], "collections": ["shared"]},
        )
    assert exc.value.args[0] == "member-members-not-denied"


def test_mint_member_cap_rejects_missing_scope_paths() -> None:
    # A cap with no `paths` is path-unrestricted: `match_scope_path(_, None)` is
    # True, so it would clear the gate for `shared/_members`/`shared/_keyring`.
    # The barrier must treat absent paths as an implicit allow-all and reject it.
    # Mirrors the TS twin in cap-mint.test.ts.
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {"ops": ["read", "list", "write"], "collections": ["shared"]},  # no `paths`
        )
    assert exc.value.args[0] == "member-members-not-denied"


def test_mint_member_cap_rejects_writer_without_keyring_deny() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {
                "ops": ["read", "write"],
                "paths": ["shared/*", "!shared/_members"],
                "collections": ["shared"],
            },
        )
    assert exc.value.args[0] == "member-keyring-not-denied"


def test_mint_member_cap_rejects_double_star_reaching_keyring() -> None:
    # _members is denied so this isolates the _keyring barrier: the `**` allow
    # still reaches shared/_keyring across the slash, which path_glob_match must
    # detect identically to the resolver's match_scope_path.
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {"ops": ["read", "write"], "paths": ["**", "!shared/_members"], "collections": ["shared"]},
        )
    assert exc.value.args[0] == "member-keyring-not-denied"


def test_mint_member_cap_rejects_double_star_reaching_members() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {"ops": ["read", "list"], "paths": ["**"], "collections": ["shared"]},
        )
    assert exc.value.args[0] == "member-members-not-denied"


def test_mint_member_cap_rejects_bare_prefix_glob_reaching_members() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "shared",
            {"ops": ["read", "list"], "paths": ["shared**"], "collections": ["shared"]},
        )
    assert exc.value.args[0] == "member-members-not-denied"


def test_mint_member_cap_accepts_writer_with_both_denies() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared",
        {
            "ops": ["read", "write"],
            "paths": ["shared/*", "!shared/_keyring", "!shared/_members"],
            "collections": ["shared"],
        },
    )
    assert cert["kind"] == "member"
    assert "!shared/_keyring" in cert["scope"]["paths"]
    assert "!shared/_members" in cert["scope"]["paths"]


def test_mint_member_cap_read_only_requires_members_deny() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared",
        {
            "ops": ["read", "list"],
            "paths": ["shared/*", "!shared/_members"],
            "collections": ["shared"],
        },
    )
    assert cert["kind"] == "member"


def test_scopes_read_only() -> None:
    s = scopes.read_only("notes")
    assert s["ops"] == ["read", "list"]
    assert s["collections"] == ["notes"]
    assert s["paths"] == ["notes/**", "!notes/_members"]


def test_scopes_writer_denies_keyring_and_members() -> None:
    s = scopes.writer("notes")
    assert "write" in s["ops"]
    assert "notes/**" in s["paths"]
    assert "!notes/_keyring" in s["paths"]
    assert "!notes/_members" in s["paths"]


def test_scopes_admin_full_write() -> None:
    s = scopes.admin("notes")
    assert "write" in s["ops"]
    assert s["paths"] == ["notes/**"]


# The admin preset has no _keyring/_members deny. That is only valid for a
# device cap, where the subject proxies for the issuer (the owner) and thus
# legitimately manages the owner's own keyring and member directory. A member
# cap keeps its own identity and must never reach those owner-only paths, so the
# same preset must be rejected when minted as a member cap.
def test_admin_preset_accepted_as_device_cap() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    dev = derive_root_identity("alice-device-passphrase")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": dev.keys.ed_pub, "kemPubHex": dev.keys.kem_pub},
        scopes.admin("notes"),
    )
    assert cert["kind"] == "device"
    result = verify_cap_cert(cert, now=cert["nbf"] + 5)
    assert result["ok"] is True


def test_admin_preset_rejected_as_member_cap() -> None:
    alice = derive_root_identity("alice-root-passphrase")
    bob = derive_root_identity("bob-root-passphrase")
    with pytest.raises(ValueError) as exc:
        mint_member_cap(
            alice.keys.ed_priv,
            alice.keys.ed_pub,
            {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
            "notes",
            scopes.admin("notes"),
        )
    assert exc.value.args[0] == "member-members-not-denied"
