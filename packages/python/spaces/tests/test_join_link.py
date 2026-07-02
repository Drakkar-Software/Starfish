"""join_space_by_link round-trips through the sync seal helpers."""

from __future__ import annotations

import json

import pytest
from starfish_sdk.types import StarfishHttpError

from starfish_spaces.account_seal import unseal_from_self
from starfish_spaces.members import join_space_by_link
from starfish_spaces.space_access_store import (
    clear_space_access_store,
    get_space_access_entry,
)
from tests.helpers import make_fake_session


@pytest.fixture(autouse=True)
def _reset():
    clear_space_access_store()
    yield
    clear_space_access_store()


class _Res:
    def __init__(self, data, hash_):
        self.data = data
        self.hash = hash_


class FakeSpacesClient:
    def __init__(self):
        self.data = None
        self.hash = None

    async def pull(self, path):
        if self.data is None:
            raise StarfishHttpError(404, "not found")
        return _Res(self.data, self.hash)

    async def push(self, path, payload, hash_):
        self.data = payload
        self.hash = "h1"


async def test_join_space_by_link_round_trips():
    client = FakeSpacesClient()
    session = make_fake_session(account_client=client)

    token = {
        "v": 1,
        "spaceId": "sp-42",
        "spaceName": "Team",
        "cap": {"kind": "member", "sub": "abc"},
        "key": "edprivhex",
        "kemPriv": "kempriv",
        "kemPub": "kempub",
        "write": True,
    }

    space = await join_space_by_link(session, token)
    assert space.id == "sp-42"

    # The sealed link-access blob was stored server-side and is self-openable.
    sealed = client.data["pubAccess"]["sp-42"]
    assert "entry" in sealed and sealed["entry"]["addedBy"] == session.keys["edPub"]
    recovered = json.loads(unseal_from_self(session, sealed))
    assert recovered["cap"] == token["cap"]
    assert recovered["key"] == token["key"]

    # Local access-store entry recorded too.
    entry = get_space_access_entry("sp-42")
    assert entry is not None and entry["kind"] == "link"
