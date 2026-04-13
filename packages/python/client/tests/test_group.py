"""Tests for group encryption utilities."""

import json
import pathlib

import pytest
from starfish_sdk.group import (
    GroupKeyPair,
    GroupKeyring,
    derive_group_key_pair,
    generate_group_key,
    wrap_group_key,
    unwrap_group_key,
    create_group_keyring,
    add_group_member,
    rotate_group_key,
    create_group_encryptor,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "group-crypto.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


# ── derive_group_key_pair ────────────────────────────────────────────────────


def test_derive_group_key_pair_returns_hex_keys():
    kp = derive_group_key_pair("hello world", "abc123")
    assert len(kp.private_key) == 64
    assert len(kp.public_key) == 64
    assert all(c in "0123456789abcdef" for c in kp.private_key)
    assert all(c in "0123456789abcdef" for c in kp.public_key)


def test_derive_group_key_pair_is_deterministic():
    a = derive_group_key_pair("my passphrase", "userid123")
    b = derive_group_key_pair("my passphrase", "userid123")
    assert a.private_key == b.private_key
    assert a.public_key == b.public_key


def test_derive_group_key_pair_different_passphrases():
    a = derive_group_key_pair("passphrase-a", "user1")
    b = derive_group_key_pair("passphrase-b", "user1")
    assert a.private_key != b.private_key
    assert a.public_key != b.public_key


def test_derive_group_key_pair_different_user_ids():
    a = derive_group_key_pair("same passphrase", "user1")
    b = derive_group_key_pair("same passphrase", "user2")
    assert a.public_key != b.public_key


def test_derive_group_key_pair_keys_are_distinct():
    kp = derive_group_key_pair("test phrase", "testuser")
    assert kp.public_key != kp.private_key


# ── generate_group_key ───────────────────────────────────────────────────────


def test_generate_group_key_returns_64_hex_chars():
    gek = generate_group_key()
    assert len(gek) == 64
    assert all(c in "0123456789abcdef" for c in gek)


def test_generate_group_key_randomness():
    keys = {generate_group_key() for _ in range(10)}
    assert len(keys) == 10


# ── wrap / unwrap ────────────────────────────────────────────────────────────


def test_wrap_unwrap_round_trip():
    admin_kp = derive_group_key_pair("admin passphrase", "adminId")
    member_kp = derive_group_key_pair("member passphrase", "memberId")
    gek = generate_group_key()

    wrapped = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)
    unwrapped = unwrap_group_key(wrapped, member_kp.private_key, admin_kp.public_key)

    assert unwrapped == gek


def test_wrapped_value_is_base64_string():
    admin_kp = derive_group_key_pair("admin", "a1")
    member_kp = derive_group_key_pair("member", "m1")
    gek = generate_group_key()
    wrapped = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)
    assert isinstance(wrapped, str)
    assert len(wrapped) > 0


def test_wrap_produces_different_ciphertext_each_time():
    admin_kp = derive_group_key_pair("admin", "a1")
    member_kp = derive_group_key_pair("member", "m1")
    gek = generate_group_key()
    wrapped1 = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)
    wrapped2 = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)
    assert wrapped1 != wrapped2


def test_unwrap_with_wrong_private_key_raises():
    admin_kp = derive_group_key_pair("admin", "a1")
    member_kp = derive_group_key_pair("member", "m1")
    wrong_kp = derive_group_key_pair("wrong", "w1")
    gek = generate_group_key()
    wrapped = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)

    with pytest.raises(ValueError):
        unwrap_group_key(wrapped, wrong_kp.private_key, admin_kp.public_key)


def test_unwrap_with_wrong_admin_public_key_raises():
    admin_kp = derive_group_key_pair("admin", "a1")
    member_kp = derive_group_key_pair("member", "m1")
    wrong_kp = derive_group_key_pair("wrong", "w1")
    gek = generate_group_key()
    wrapped = wrap_group_key(gek, member_kp.public_key, admin_kp.private_key)

    with pytest.raises(ValueError):
        unwrap_group_key(wrapped, member_kp.private_key, wrong_kp.public_key)


# ── create_group_keyring ─────────────────────────────────────────────────────


def test_create_group_keyring_structure():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    bob_kp = derive_group_key_pair("bob", "b")
    keyring, gek = create_group_keyring(admin_kp, {"alice": alice_kp.public_key, "bob": bob_kp.public_key})

    assert keyring.current_epoch == 1
    assert "1" in keyring.epochs
    assert "alice" in keyring.epochs["1"].wrapped_keys
    assert "bob" in keyring.epochs["1"].wrapped_keys
    assert len(gek) == 64


def test_create_group_keyring_all_members_can_unwrap():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, gek = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    alice_gek = unwrap_group_key(
        keyring.epochs["1"].wrapped_keys["alice"],
        alice_kp.private_key,
        keyring.epochs["1"].admin_public_key,
    )
    assert alice_gek == gek


def test_create_group_keyring_accepts_explicit_gek():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    my_gek = generate_group_key()
    _, returned_gek = create_group_keyring(admin_kp, {"alice": alice_kp.public_key}, gek=my_gek)
    assert returned_gek == my_gek


def test_create_group_keyring_to_dict_round_trip():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    d = keyring.to_dict()
    restored = GroupKeyring.from_dict(d)
    assert restored.current_epoch == keyring.current_epoch
    assert restored.epochs["1"].admin_public_key == keyring.epochs["1"].admin_public_key
    assert restored.epochs["1"].wrapped_keys == keyring.epochs["1"].wrapped_keys


# ── add_group_member ─────────────────────────────────────────────────────────


def test_add_group_member_new_member_can_unwrap():
    admin_kp = derive_group_key_pair("admin", "adm")
    alice_kp = derive_group_key_pair("alice", "ali")
    charlie_kp = derive_group_key_pair("charlie", "cha")
    keyring, gek = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    updated = add_group_member(keyring, admin_kp, gek, "charlie", charlie_kp.public_key)
    assert "charlie" in updated.epochs["1"].wrapped_keys

    charlie_gek = unwrap_group_key(
        updated.epochs["1"].wrapped_keys["charlie"],
        charlie_kp.private_key,
        updated.epochs["1"].admin_public_key,
    )
    assert charlie_gek == gek


def test_add_group_member_wrong_key_pair_raises():
    admin_kp = derive_group_key_pair("admin", "a")
    wrong_kp = derive_group_key_pair("wrong", "w")
    alice_kp = derive_group_key_pair("alice", "b")
    keyring, gek = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    with pytest.raises(ValueError, match="does not match"):
        add_group_member(keyring, wrong_kp, gek, "new", alice_kp.public_key)


# ── rotate_group_key ─────────────────────────────────────────────────────────


def test_rotate_group_key_creates_new_epoch():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    bob_kp = derive_group_key_pair("bob", "b")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key, "bob": bob_kp.public_key})

    rotated, new_gek = rotate_group_key(keyring, admin_kp, {"alice": alice_kp.public_key})

    assert rotated.current_epoch == 2
    assert "1" in rotated.epochs  # old epoch preserved
    assert "2" in rotated.epochs  # new epoch
    assert "alice" in rotated.epochs["2"].wrapped_keys
    assert "bob" not in rotated.epochs["2"].wrapped_keys
    assert len(new_gek) == 64


def test_rotate_group_key_removed_member_has_no_entry():
    admin_kp = derive_group_key_pair("admin", "a")
    bob_kp = derive_group_key_pair("bob", "b")
    keyring, _ = create_group_keyring(admin_kp, {"bob": bob_kp.public_key})

    rotated, _ = rotate_group_key(keyring, admin_kp, {})
    assert "bob" not in rotated.epochs["2"].wrapped_keys


def test_rotate_group_key_wrong_key_pair_raises():
    admin_kp = derive_group_key_pair("admin", "a")
    wrong_kp = derive_group_key_pair("wrong", "w")
    alice_kp = derive_group_key_pair("alice", "b")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    with pytest.raises(ValueError, match="does not match"):
        rotate_group_key(keyring, wrong_kp, {"alice": alice_kp.public_key})


# ── create_group_encryptor ───────────────────────────────────────────────────


def test_group_encryptor_encrypt_decrypt():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    encryptor = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    plaintext = {"message": "hello group", "ts": 12345}
    encrypted = encryptor.encrypt(plaintext)
    decrypted = encryptor.decrypt(encrypted)

    assert decrypted == plaintext


def test_group_encryptor_includes_epoch_field():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    encryptor = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    encrypted = encryptor.encrypt({"x": 1})
    assert encrypted["_epoch"] == 1


def test_group_encryptor_decrypts_older_epochs():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    enc1 = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    old_doc = enc1.encrypt({"era": "epoch-1"})
    assert old_doc["_epoch"] == 1

    rotated, _ = rotate_group_key(keyring, admin_kp, {"alice": alice_kp.public_key})

    enc2 = create_group_encryptor(rotated, "alice", alice_kp.private_key)
    new_doc = enc2.encrypt({"era": "epoch-2"})
    assert new_doc["_epoch"] == 2

    old_decrypted = enc2.decrypt(old_doc)
    assert old_decrypted == {"era": "epoch-1"}


def test_group_encryptor_unknown_identity_raises():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    with pytest.raises(ValueError, match="No wrapped key found"):
        create_group_encryptor(keyring, "nobody", alice_kp.private_key)


def test_group_encryptor_unknown_epoch_raises():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    encryptor = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    fake_doc = {"_encrypted": "not-real", "_epoch": 99}
    with pytest.raises(ValueError, match="No key available for epoch"):
        encryptor.decrypt(fake_doc)


def test_group_encryptor_missing_epoch_falls_back_to_current():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key})

    encryptor = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    plaintext = {"msg": "legacy doc"}

    # Encrypt normally (has _epoch), then strip _epoch to simulate a legacy document
    encrypted = encryptor.encrypt(plaintext)
    without_epoch = {k: v for k, v in encrypted.items() if k != "_epoch"}
    decrypted = encryptor.decrypt(without_epoch)
    assert decrypted == plaintext


def test_group_encryptor_cross_member_decryption():
    admin_kp = derive_group_key_pair("admin", "a")
    alice_kp = derive_group_key_pair("alice", "a")
    bob_kp = derive_group_key_pair("bob", "b")
    keyring, _ = create_group_keyring(admin_kp, {"alice": alice_kp.public_key, "bob": bob_kp.public_key})

    alice_enc = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    bob_enc = create_group_encryptor(keyring, "bob", bob_kp.private_key)

    alice_msg = alice_enc.encrypt({"from": "alice", "text": "hi"})
    bob_decrypted = bob_enc.decrypt(alice_msg)
    assert bob_decrypted == {"from": "alice", "text": "hi"}

    bob_msg = bob_enc.encrypt({"from": "bob", "text": "hey"})
    alice_decrypted = alice_enc.decrypt(bob_msg)
    assert alice_decrypted == {"from": "bob", "text": "hey"}


# ── Cross-language test vectors ───────────────────────────────────────────────


def test_vector_derive_admin_key_pair():
    """Deterministic key pair derivation must match the published test vector."""
    v = VECTORS["keypairs"]["admin"]
    kp = derive_group_key_pair(v["passphrase"], v["userId"])
    assert kp.private_key == v["privateKey"]
    assert kp.public_key == v["publicKey"]


def test_vector_derive_alice_key_pair():
    v = VECTORS["keypairs"]["alice"]
    kp = derive_group_key_pair(v["passphrase"], v["userId"])
    assert kp.private_key == v["privateKey"]
    assert kp.public_key == v["publicKey"]


def test_vector_derive_bob_key_pair():
    v = VECTORS["keypairs"]["bob"]
    kp = derive_group_key_pair(v["passphrase"], v["userId"])
    assert kp.private_key == v["privateKey"]
    assert kp.public_key == v["publicKey"]


def test_vector_unwrap_alice_key():
    """Unwrap the pre-generated wrapped key for alice and recover the fixed GEK.

    This vector was generated by the Python implementation and must also pass
    in TypeScript, proving both sides share the same ECDH+HKDF+AES-GCM chain.
    """
    w = VECTORS["wrapping"]
    kp = VECTORS["keypairs"]
    recovered = unwrap_group_key(
        w["wrappedForAlice"],
        kp["alice"]["privateKey"],
        kp["admin"]["publicKey"],
    )
    assert recovered == w["gek"]


def test_vector_unwrap_bob_key():
    """Unwrap the pre-generated wrapped key for bob and recover the fixed GEK."""
    w = VECTORS["wrapping"]
    kp = VECTORS["keypairs"]
    recovered = unwrap_group_key(
        w["wrappedForBob"],
        kp["bob"]["privateKey"],
        kp["admin"]["publicKey"],
    )
    assert recovered == w["gek"]


def test_vector_wrap_then_unwrap_roundtrip():
    """Wrap with the vector admin key, unwrap with the vector alice key — full round-trip."""
    kp = VECTORS["keypairs"]
    gek = VECTORS["wrapping"]["gek"]

    wrapped = wrap_group_key(gek, kp["alice"]["publicKey"], kp["admin"]["privateKey"])
    recovered = unwrap_group_key(wrapped, kp["alice"]["privateKey"], kp["admin"]["publicKey"])
    assert recovered == gek


def test_vector_keyring_all_members_can_decrypt():
    """Verify that both alice and bob can decrypt a document encrypted by alice,
    using the vector key pairs and fixed GEK."""
    kp_data = VECTORS["keypairs"]
    w = VECTORS["wrapping"]

    admin_kp = GroupKeyPair(
        private_key=kp_data["admin"]["privateKey"],
        public_key=kp_data["admin"]["publicKey"],
    )
    alice_kp = GroupKeyPair(
        private_key=kp_data["alice"]["privateKey"],
        public_key=kp_data["alice"]["publicKey"],
    )
    bob_kp = GroupKeyPair(
        private_key=kp_data["bob"]["privateKey"],
        public_key=kp_data["bob"]["publicKey"],
    )

    keyring, gek = create_group_keyring(
        admin_kp,
        {"alice": alice_kp.public_key, "bob": bob_kp.public_key},
        gek=w["gek"],
    )
    assert gek == w["gek"]

    alice_enc = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    bob_enc = create_group_encryptor(keyring, "bob", bob_kp.private_key)

    plaintext = {"msg": "cross-lang test", "n": 42}
    encrypted = alice_enc.encrypt(plaintext)
    assert encrypted["_epoch"] == 1

    assert bob_enc.decrypt(encrypted) == plaintext
    assert alice_enc.decrypt(encrypted) == plaintext


def test_vector_decrypt_python_encrypted_data():
    """Both alice and bob must decrypt a document that was pre-encrypted by Python.

    This is stored in the test vectors so TypeScript can also run the same check,
    proving the full encrypt/decrypt pipeline is cross-language compatible.
    """
    kp_data = VECTORS["keypairs"]
    w = VECTORS["wrapping"]
    d = VECTORS["dataEncryption"]

    admin_kp = GroupKeyPair(
        private_key=kp_data["admin"]["privateKey"],
        public_key=kp_data["admin"]["publicKey"],
    )
    alice_kp = GroupKeyPair(
        private_key=kp_data["alice"]["privateKey"],
        public_key=kp_data["alice"]["publicKey"],
    )
    bob_kp = GroupKeyPair(
        private_key=kp_data["bob"]["privateKey"],
        public_key=kp_data["bob"]["publicKey"],
    )

    keyring, _ = create_group_keyring(
        admin_kp,
        {"alice": alice_kp.public_key, "bob": bob_kp.public_key},
        gek=w["gek"],
    )

    alice_enc = create_group_encryptor(keyring, "alice", alice_kp.private_key)
    bob_enc = create_group_encryptor(keyring, "bob", bob_kp.private_key)

    assert alice_enc.decrypt(d["encryptedByPython"]) == d["plaintext"]
    assert bob_enc.decrypt(d["encryptedByPython"]) == d["plaintext"]
