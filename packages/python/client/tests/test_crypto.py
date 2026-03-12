"""Tests for client-side encryption."""

import json
import pathlib

import pytest

from starfish_sdk.crypto import Encryptor, ENCRYPTED_KEY, create_encryptor


VECTORS_PATH = pathlib.Path(__file__).parent.parent.parent.parent.parent / "tests" / "test-vectors" / "crypto.json"
VECTORS = json.loads(VECTORS_PATH.read_text())


def test_round_trip():
    enc = Encryptor("test-secret", "test-salt")
    data = {"hello": "world", "num": 42}

    encrypted = enc.encrypt(data)
    assert ENCRYPTED_KEY in encrypted
    assert isinstance(encrypted[ENCRYPTED_KEY], str)

    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


def test_decrypt_rejects_unencrypted():
    enc = Encryptor("test-secret", "test-salt")
    plain = {"plain": "data"}

    with pytest.raises(ValueError, match="Expected encrypted data but received unencrypted document"):
        enc.decrypt(plain)


def test_different_secrets():
    enc1 = Encryptor("secret-1", "salt")
    enc2 = Encryptor("secret-2", "salt")
    data = {"key": "value"}

    encrypted = enc1.encrypt(data)
    try:
        enc2.decrypt(encrypted)
        assert False, "Should have raised"
    except Exception:
        pass


def test_different_salts():
    enc1 = Encryptor("secret", "salt-1")
    enc2 = Encryptor("secret", "salt-2")
    data = {"key": "value"}

    encrypted = enc1.encrypt(data)
    try:
        enc2.decrypt(encrypted)
        assert False, "Should have raised"
    except Exception:
        pass


def test_custom_info():
    enc = Encryptor("secret", "salt", info="custom-info")
    data = {"custom": True}

    encrypted = enc.encrypt(data)
    decrypted = enc.decrypt(encrypted)
    assert decrypted == data


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: str(v["plaintext"])[:60])
def test_decrypt_vector(vector):
    enc = Encryptor(VECTORS["secret"], VECTORS["salt"])
    wrapper = {ENCRYPTED_KEY: vector["encrypted"]}
    decrypted = enc.decrypt(wrapper)
    assert decrypted == vector["plaintext"]


def test_create_encryptor_rejects_empty_secret():
    with pytest.raises(ValueError, match="secret"):
        create_encryptor("", "salt")


def test_create_encryptor_rejects_empty_salt():
    with pytest.raises(ValueError, match="salt"):
        create_encryptor("secret", "")
