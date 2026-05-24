"""Unit tests for `evict_member` — the one-call rotate + revoke + de-roster helper."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_protocol import revocation_list_canonical_signing_input
from starfish_protocol.types import PullResult, PushSuccess
from starfish_sdk.client import StarfishClient
from starfish_sdk.types import StarfishHttpError
from starfish_keyring import create_keyring
from starfish_keyring.recipients import keyring_path_for
from starfish_sharing import evict_member
from starfish_sharing.directory import members_path_for


def _raw(priv, pub):
    return (
        priv.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        ).hex(),
        pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
    )


class _Party:
    def __init__(self) -> None:
        ed = Ed25519PrivateKey.generate()
        kem = X25519PrivateKey.generate()
        self.ed_priv, self.ed_pub = _raw(ed, ed.public_key())
        self.kem_priv, self.kem_pub = _raw(kem, kem.public_key())


def _make_client(initial: dict[str, dict]) -> tuple[StarfishClient, dict]:
    """In-memory fake client keyed by request path. `initial` maps pull-path → doc dict."""
    store: dict[str, dict] = {f"/pull/{k}": {"data": v, "hash": "h0"} for k, v in initial.items()}
    counter = {"n": 0}
    client = StarfishClient.__new__(StarfishClient)

    async def _pull(path: str, checkpoint: int = 0) -> PullResult:
        entry = store.get(path)
        if entry is None:
            raise StarfishHttpError(404, "not found")
        return PullResult(data=entry["data"], hash=entry["hash"], timestamp=1000)

    async def _push(path: str, data: dict, base_hash=None, sig=None) -> PushSuccess:
        counter["n"] += 1
        # Mirror the push back onto the matching pull path so reads see the update.
        store[path.replace("/push/", "/pull/", 1)] = {"data": data, "hash": f"h{counter['n']}"}
        return PushSuccess(hash=f"h{counter['n']}", timestamp=2000)

    client.pull = AsyncMock(side_effect=_pull)  # type: ignore[attr-defined]
    client.push = AsyncMock(side_effect=_push)  # type: ignore[attr-defined]
    return client, store


def _ed_verify(pub_hex: str, sig_b64: str, message: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            base64.b64decode(sig_b64), message.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError):
        return False


_NONCE = base64.b64encode(b"\x11" * 16).decode()
_MEMBER_SUB = "cd" * 32


def _member(party: _Party) -> dict:
    return {"sub": _MEMBER_SUB, "nonce": _NONCE, "exp": 1999999999, "subKem": party.kem_pub}


@pytest.mark.asyncio
async def test_evict_member_noop_when_both_flags_false():
    owner, member = _Party(), _Party()
    client, _ = _make_client({})
    captured: list = []

    result = await evict_member(
        client,
        keyring_collection="room",
        members_collection="room",
        member=_member(member),
        adder={"edPriv": owner.ed_priv, "edPub": owner.ed_pub, "kemPriv": owner.kem_priv},
        trusted_adders=[owner.ed_pub],
        iss_ed_pub_hex=owner.ed_pub,
        iss_ed_priv_hex=owner.ed_priv,
        generation=1,
        submit_revocation=lambda lst: captured.append(lst),  # type: ignore[arg-type]
        rotate=False,
        revoke=False,
    )

    assert result == {"revoked": False}
    assert captured == []
    client.push.assert_not_called()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_evict_member_rotates_revokes_and_de_rosters():
    owner, member = _Party(), _Party()
    keyring, _cek = create_keyring(owner.ed_priv, owner.ed_pub, [owner.kem_pub, member.kem_pub])
    directory = {"v": 1, "entries": [{"nonce": _NONCE, "subUserId": "deadbeef", "sub": _MEMBER_SUB}]}
    client, store = _make_client(
        {keyring_path_for("room"): keyring.to_dict(), members_path_for("room"): directory}
    )

    captured: list = []

    async def _submit(lst):
        captured.append(lst)

    prior = [{"sub": "ab" * 32, "nonce": base64.b64encode(b"\x22" * 16).decode(), "exp": 1999999999}]
    result = await evict_member(
        client,
        keyring_collection="room",
        members_collection="room",
        member=_member(member),
        adder={"edPriv": owner.ed_priv, "edPub": owner.ed_pub, "kemPriv": owner.kem_priv},
        trusted_adders=[owner.ed_pub],
        iss_ed_pub_hex=owner.ed_pub,
        iss_ed_priv_hex=owner.ed_priv,
        generation=7,
        submit_revocation=_submit,
        prior_revoked=prior,
        rotate=True,
        revoke=True,
    )

    # (a) rotated → a new epoch was minted.
    assert result["newEpoch"] == 2
    assert result["revoked"] is True

    # (b) a single signed list was submitted; it verifies and names prior + the member.
    assert len(captured) == 1
    lst = captured[0]
    assert lst["generation"] == 7
    assert len(lst["issUserId"]) == 32  # 128-bit issuer id
    assert _ed_verify(owner.ed_pub, lst["sig"], revocation_list_canonical_signing_input(lst))
    subs = {(e["sub"], e["nonce"]) for e in lst["revoked"]}
    assert (_MEMBER_SUB, _NONCE) in subs
    assert (prior[0]["sub"], prior[0]["nonce"]) in subs  # prior carried forward

    # (c) the member's directory entry is gone.
    updated_dir = store[f"/pull/{members_path_for('room')}"]["data"]
    assert all(e["nonce"] != _NONCE for e in updated_dir["entries"])

    # The dropped recipient is absent from the rotated epoch.
    rotated = store[f"/pull/{keyring_path_for('room')}"]["data"]
    assert all(e["subKem"] != member.kem_pub for e in rotated["epochs"]["2"]["wrappedKeys"])


@pytest.mark.asyncio
async def test_evict_member_revoke_only_without_keyring_params():
    owner, member = _Party(), _Party()
    directory = {"v": 1, "entries": [{"nonce": _NONCE, "subUserId": "deadbeef", "sub": _MEMBER_SUB}]}
    client, store = _make_client({members_path_for("board"): directory})

    captured: list = []

    async def _submit(lst):
        captured.append(lst)

    result = await evict_member(
        client,
        members_collection="board",
        member=_member(member),
        iss_ed_pub_hex=owner.ed_pub,
        iss_ed_priv_hex=owner.ed_priv,
        generation=3,
        submit_revocation=_submit,
        rotate=False,
        revoke=True,
    )

    assert result["revoked"] is True
    assert "newEpoch" not in result
    assert len(captured) == 1
    updated_dir = store[f"/pull/{members_path_for('board')}"]["data"]
    assert all(e["nonce"] != _NONCE for e in updated_dir["entries"])


@pytest.mark.asyncio
async def test_evict_member_rotate_without_keyring_params_raises():
    owner, member = _Party(), _Party()
    client, _ = _make_client({})

    with pytest.raises(ValueError, match="requires keyring_collection"):
        await evict_member(
            client,
            members_collection="board",
            member=_member(member),
            iss_ed_pub_hex=owner.ed_pub,
            iss_ed_priv_hex=owner.ed_priv,
            generation=1,
            submit_revocation=lambda lst: None,  # type: ignore[arg-type]
            rotate=True,
            revoke=False,
        )
