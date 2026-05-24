"""Unit + cross-language vector tests for passphrase-sealed envelopes."""

import base64
import copy
import json
import pathlib
from unittest import mock

import pytest

from starfish_identities.identity import (
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
)
from starfish_identities.seal import (
    is_sealed_envelope,
    open_with_passphrase,
    seal_with_passphrase,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "passphrase-seal.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def _flip(s: str) -> str:
    """Flip the first base64 char to a different valid one (keeps length)."""
    return ("B" if s[0] == "A" else "A") + s[1:]


# ── Roundtrip ────────────────────────────────────────────────────────────────


def test_roundtrip_opens_to_exact_plaintext() -> None:
    pt = b"a secret setup code"
    env = seal_with_passphrase("hunter2", pt)
    assert open_with_passphrase("hunter2", env) == pt


def test_rejects_empty_passphrase_at_seal_time() -> None:
    with pytest.raises(ValueError):
        seal_with_passphrase("", b"x")


def test_fresh_random_salt_and_iv_each_time() -> None:
    a = seal_with_passphrase("pw", b"same")
    b = seal_with_passphrase("pw", b"same")
    assert a["kdf"]["salt"] != b["kdf"]["salt"]
    assert a["iv"] != b["iv"]
    assert a["ct"] != b["ct"]


# ── Failure parity (one generic error) ───────────────────────────────────────


def test_wrong_passphrase_and_tampered_ct_raise_same_message() -> None:
    env = seal_with_passphrase("right", b"payload")

    with pytest.raises(ValueError) as wrong_pass:
        open_with_passphrase("wrong", env)

    tampered = copy.deepcopy(env)
    tampered["ct"] = _flip(tampered["ct"])
    with pytest.raises(ValueError) as tampered_ct:
        open_with_passphrase("right", tampered)

    assert str(wrong_pass.value) == str(tampered_ct.value)


def test_tampered_salt_and_iv_raise_generic_error() -> None:
    env = seal_with_passphrase("right", b"payload")

    bad_salt = copy.deepcopy(env)
    bad_salt["kdf"]["salt"] = _flip(bad_salt["kdf"]["salt"])
    with pytest.raises(ValueError, match="Failed to open sealed envelope"):
        open_with_passphrase("right", bad_salt)

    bad_iv = copy.deepcopy(env)
    bad_iv["iv"] = _flip(bad_iv["iv"])
    with pytest.raises(ValueError, match="Failed to open sealed envelope"):
        open_with_passphrase("right", bad_iv)


# ── NFC normalization ────────────────────────────────────────────────────────


def test_decomposed_and_composed_passphrase_open_same_envelope() -> None:
    # Build both forms from code points so the source stays pure-ASCII and the
    # composed/decomposed distinction can't be flattened by an editor.
    composed = "caf" + chr(0x00E9)  # "caf" + e-acute (single code point U+00E9)
    decomposed = "cafe" + chr(0x0301)  # "cafe" + combining acute U+0301
    assert composed != decomposed
    env = seal_with_passphrase(composed, "unicode payload".encode("utf-8"))
    assert open_with_passphrase(decomposed, env).decode("utf-8") == "unicode payload"


# ── Type guard ───────────────────────────────────────────────────────────────


def test_is_sealed_envelope() -> None:
    env = seal_with_passphrase("pw", b"x")
    assert is_sealed_envelope(env) is True
    assert is_sealed_envelope({"v": 1, "keys": {}, "bundle": {}, "roomId": "general"}) is False
    assert is_sealed_envelope(None) is False
    assert is_sealed_envelope("not a dict") is False
    assert is_sealed_envelope({"v": 1, "enc": "passphrase", "iv": "x", "ct": "y"}) is False


# ── Cross-language vectors ────────────────────────────────────────────────────


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["label"])
def test_opens_cross_language_vector_to_plaintext(vector: dict) -> None:
    out = open_with_passphrase(vector["passphrase"], vector["envelope"])
    assert out.decode("utf-8") == vector["plaintextUtf8"]


@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: v["label"])
def test_reproduces_cross_language_vector_envelope(vector: dict) -> None:
    env = seal_with_passphrase(
        vector["passphrase"],
        vector["plaintextUtf8"].encode("utf-8"),
        salt=base64.b64decode(vector["saltB64"]),
        iv=base64.b64decode(vector["ivB64"]),
    )
    assert env == vector["envelope"]


# ── DoS guard: reject hostile envelopes before invoking Argon2id ─────────────


def _envelope_with(*, enc: str = "passphrase", **kdf_overrides) -> dict:
    kdf = {
        "alg": "argon2id",
        "memKiB": ARGON2_MEMORY_KIB,
        "iter": ARGON2_ITERATIONS,
        "par": ARGON2_PARALLELISM,
        "salt": base64.b64encode(b"\x00" * 16).decode("ascii"),
    }
    kdf.update(kdf_overrides)
    return {
        "v": 1,
        "enc": enc,
        "kdf": kdf,
        "iv": base64.b64encode(b"\x00" * 12).decode("ascii"),
        "ct": base64.b64encode(b"\x00" * 32).decode("ascii"),
    }


@pytest.mark.parametrize(
    "envelope",
    [
        _envelope_with(memKiB=4_000_000),
        _envelope_with(iter=10_000_000),
        _envelope_with(par=255),
        _envelope_with(alg="scrypt"),
        _envelope_with(enc="rot13"),
        _envelope_with(salt=base64.b64encode(b"\x00" * 3).decode("ascii")),
    ],
    ids=["inflated-mem", "inflated-iter", "inflated-par", "unknown-alg", "unknown-enc", "short-salt"],
)
def test_rejects_hostile_envelope_without_invoking_argon2id(envelope: dict) -> None:
    spy = mock.Mock(return_value=b"\x00" * 32)
    with mock.patch("starfish_identities.seal.hash_secret_raw", spy):
        with pytest.raises(ValueError):
            open_with_passphrase("pw", envelope)
    spy.assert_not_called()
