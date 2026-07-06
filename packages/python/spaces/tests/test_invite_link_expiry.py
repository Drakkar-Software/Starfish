"""Hardening of the single-link space-invite flow (Python mirror of the TS tests).

Covers the shared ``assert_cap_not_expired`` guard, owner-settable expiry baked
into the cap by ``create_space_invite_link`` (``ttl_sec`` / ``expires_at``), the
returned ``inviteUserId`` revocation handle, and ``join_space_by_link`` refusing
a dead link before any network work.

Only the two network-touching collaborators are patched (roster write + keyring
recipiency); the real ``mint_member_cap`` runs so the asserted ``nbf``/``exp``
are the actual server-enforced values.
"""

from __future__ import annotations

import re
import time

import pytest
from starfish_sharing.cap_mint import MintOpts

import starfish_spaces.members as members_mod
from starfish_spaces.invite_helpers import assert_cap_not_expired
from starfish_spaces.members import (
    clear_space_invite_store,
    create_space_invite_link,
    get_space_invite_entry,
    join_space_by_link,
)
from tests.helpers import make_fake_session

DAY = 24 * 3600
HEX32 = re.compile(r"^[0-9a-f]{32}$")


@pytest.fixture(autouse=True)
def _patch_network(monkeypatch):
    """No-op the roster write + keyring recipiency; let mint_member_cap run for real."""
    clear_space_invite_store()

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(members_mod, "add_space_member", _noop)
    monkeypatch.setattr(members_mod, "ensure_space_keyring_recipient", _noop)
    yield
    clear_space_invite_store()


# ── assert_cap_not_expired (pure) ───────────────────────────────────────────


def test_guard_passes_for_future_exp():
    assert_cap_not_expired({"exp": int(time.time()) + 3600}, "e")  # no raise


def test_guard_passes_in_active_window():
    now = int(time.time())
    assert_cap_not_expired({"nbf": now - 10, "exp": now + 3600}, "e")  # no raise


def test_guard_raises_on_expired():
    with pytest.raises(ValueError, match=r"Nope: this invite link has expired\."):
        assert_cap_not_expired({"exp": int(time.time()) - 1}, "Nope")


def test_guard_raises_on_not_yet_valid():
    now = int(time.time())
    with pytest.raises(ValueError, match=r"Nope: this invite link is not yet valid\."):
        assert_cap_not_expired({"nbf": now + 3600, "exp": now + 7200}, "Nope")


def test_guard_is_lenient_without_exp():
    assert_cap_not_expired({"kind": "member"}, "e")
    assert_cap_not_expired(None, "e")
    assert_cap_not_expired("not-a-dict", "e")


# ── create_space_invite_link: expiry + revocation handle ────────────────────


async def test_ttl_sec_bounds_cap_exp():
    session = make_fake_session()
    result = await create_space_invite_link(session, "sp-1", "Team", True, "https://app", MintOpts(ttl_sec=3600))
    cap = result["token"]["cap"]
    assert cap["exp"] - cap["nbf"] == 3600


async def test_default_ttl_is_30_days():
    session = make_fake_session()
    result = await create_space_invite_link(session, "sp-1", "Team", True, "https://app")
    cap = result["token"]["cap"]
    assert cap["exp"] - cap["nbf"] == 30 * DAY


async def test_expires_at_wins():
    session = make_fake_session()
    future = int(time.time()) + 12_345
    result = await create_space_invite_link(
        session, "sp-1", "Team", True, "https://app", MintOpts(expires_at=future)
    )
    assert result["token"]["cap"]["exp"] == future


async def test_invite_user_id_is_the_revocation_handle():
    session = make_fake_session()
    result = await create_space_invite_link(session, "sp-9", "Team", True, "https://app", MintOpts(ttl_sec=600))
    cap = result["token"]["cap"]
    invite_user_id = result["inviteUserId"]

    assert HEX32.match(invite_user_id)
    assert cap["subUserId"] == invite_user_id  # the link's ephemeral member IS inviteUserId
    assert "#" in result["link"]  # secret rides in the URL fragment

    stored = get_space_invite_entry("sp-9", invite_user_id)
    assert stored is not None
    assert stored["cap"]["exp"] == cap["exp"]


async def test_each_link_is_independently_revocable():
    session = make_fake_session()
    a = await create_space_invite_link(session, "sp-1", "Team", True, "https://app", MintOpts(ttl_sec=600))
    b = await create_space_invite_link(session, "sp-1", "Team", True, "https://app", MintOpts(ttl_sec=600))
    assert a["inviteUserId"] != b["inviteUserId"]
    assert get_space_invite_entry("sp-1", a["inviteUserId"]) is not None
    assert get_space_invite_entry("sp-1", b["inviteUserId"]) is not None


# ── join_space_by_link: refuse dead links up front ──────────────────────────


async def test_join_rejects_expired_link():
    past = int(time.time()) - 10
    token = {"v": 1, "spaceId": "sp", "spaceName": "x", "cap": {"exp": past}, "key": "k", "write": False}
    with pytest.raises(ValueError, match=r"no longer usable: this invite link has expired\."):
        await join_space_by_link(make_fake_session(), token)


async def test_join_rejects_not_yet_valid_link():
    soon = int(time.time()) + 3600
    token = {"v": 1, "spaceId": "sp", "spaceName": "x", "cap": {"nbf": soon, "exp": soon + 10}, "key": "k", "write": False}
    with pytest.raises(ValueError, match=r"no longer usable: this invite link is not yet valid\."):
        await join_space_by_link(make_fake_session(), token)


async def test_freshly_minted_link_passes_the_guard():
    session = make_fake_session()
    result = await create_space_invite_link(session, "sp-1", "Team", True, "https://app", MintOpts(ttl_sec=3600))
    # Same guard join_space_by_link runs — must not raise for a fresh cap.
    assert_cap_not_expired(result["token"]["cap"], "no longer usable")
