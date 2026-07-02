"""join_node_by_link round-trips through the sync seal helpers.

Guards the node-tier counterpart of the account_seal await/attribute bug: the
sealed link-access blobs must be stored as whole dicts (openable by
``unseal_from_self``), not attribute-accessed on a coroutine.
"""

from __future__ import annotations

import json

import pytest
from starfish_sdk.types import StarfishHttpError

from starfish_spaces.account_seal import unseal_from_self
from starfish_spaces.nodes import join_node_by_link
from starfish_spaces.space_access_store import clear_space_access_store
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


async def test_join_node_by_link_round_trips():
    client = FakeSpacesClient()
    session = make_fake_session(account_client=client)

    token = {
        "v": 1,
        "spaceId": "sp-1",
        "nodeId": "nd-9",
        "nodeName": "Doc",
        "cap": {"kind": "member", "sub": "abc"},
        "key": "edprivhex",
        "write": True,
        "streamCap": {"kind": "member", "sub": "stream"},
    }

    node_id = await join_node_by_link(session, token)
    assert node_id == "nd-9"

    pub = client.data["pubAccess"]
    # Node access blob is stored as a whole self-sealed dict (not {v,ct,wks}),
    # signed by the joining account, and re-openable.
    sealed = pub["sp-1:nd-9"]
    assert "entry" in sealed and sealed["entry"]["addedBy"] == session.keys["edPub"]
    recovered = json.loads(unseal_from_self(session, sealed))
    assert recovered["cap"] == token["cap"]
    assert recovered["key"] == token["key"]

    # The optional stream branch is stored the same way.
    sealed_stream = pub["sp-1:nd-9:stream"]
    assert json.loads(unseal_from_self(session, sealed_stream))["cap"] == token["streamCap"]
