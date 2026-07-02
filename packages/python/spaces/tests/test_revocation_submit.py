"""Revocation submission is threaded through eviction (not dropped)."""

from __future__ import annotations

from types import SimpleNamespace

import starfish_spaces.invite_helpers as invite_helpers
import starfish_spaces.members as members
from starfish_spaces.invite_helpers import evict_keyring_member
from starfish_spaces.members import (
    revoke_space_access,
    save_space_invite_entry,
)
from tests.helpers import make_fake_session


async def test_evict_keyring_member_forwards_submit_revocation(monkeypatch):
    captured = {}
    revocation_list = {"generation": 7, "revoked": []}

    async def fake_evict_member(client, **kw):
        captured.update(kw)
        # Simulate the sharing layer POSTing the signed revocation list.
        await kw["submit_revocation"](revocation_list)
        return {"revoked": True}

    monkeypatch.setattr(invite_helpers, "evict_member", fake_evict_member)

    session = make_fake_session()
    got = []

    async def my_submit(rl):
        got.append(rl)

    member_entry = {"sub": "aa", "nonce": "n", "exp": 1, "subKem": "bb"}
    await evict_keyring_member(
        None, session, "coll", member_entry, 7, None, my_submit
    )

    assert got == [revocation_list]
    assert captured["submit_revocation"] is my_submit


async def test_evict_keyring_member_defaults_to_noop(monkeypatch):
    captured = {}

    async def fake_evict_member(client, **kw):
        captured.update(kw)
        # Default callback must be callable + awaitable without error.
        await kw["submit_revocation"]({"generation": 1})
        return {"revoked": True}

    monkeypatch.setattr(invite_helpers, "evict_member", fake_evict_member)

    session = make_fake_session()
    member_entry = {"sub": "aa", "nonce": "n", "exp": 1, "subKem": "bb"}
    await evict_keyring_member(None, session, "coll", member_entry, 1)

    assert callable(captured["submit_revocation"])


async def test_revoke_space_access_forwards_opts_submit(monkeypatch):
    captured = {}

    async def fake_evict_keyring_member(client, session, coll, member, gen, prior=None, submit=None):
        captured["submit"] = submit
        return {"revoked": True}

    async def fake_remove_space_member(client, space_id, user_id, session):
        return None

    monkeypatch.setattr(members, "evict_keyring_member", fake_evict_keyring_member)
    monkeypatch.setattr(members, "remove_space_member", fake_remove_space_member)

    session = make_fake_session(content_client=object(), account_client=object())
    space_id, user_id = "sp-1", "user-1"
    save_space_invite_entry(
        space_id, user_id,
        {"edPub": "ee", "kemPub": "kk", "cap": {"nonce": "n", "exp": 2}},
    )

    calls = []

    async def my_submit(rl):
        calls.append(rl)

    result = await revoke_space_access(
        session, space_id, user_id,
        {"generation": 3, "submitRevocation": my_submit},
    )

    assert result == {"revoked": True}
    assert captured["submit"] is my_submit
