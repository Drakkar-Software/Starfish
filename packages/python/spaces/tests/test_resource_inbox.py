"""Resource-request inbox: sync seal round-trip + fail-closed sender check."""

from __future__ import annotations

import json

import pytest

import starfish_spaces.client as spaces_client
import starfish_spaces.resource_requests as rr
from starfish_spaces.identity_link import IdentityLink
from starfish_spaces.request_verify import sign_kem_sig
from starfish_spaces.resource_requests import (
    clear_req_id_owner_store,
    scan_resource_requests,
    submit_resource_request,
)
from tests.helpers import make_fake_session, user_id_for


@pytest.fixture(autouse=True)
def _reset():
    clear_req_id_owner_store()
    yield
    clear_req_id_owner_store()


class FakeAnon:
    """Anonymous client: appends to a shared inbox, no reachable profile."""

    def __init__(self, inbox):
        self.inbox = inbox

    async def append_anonymous(self, path, element, *args, **kwargs):
        self.inbox.setdefault(path, []).append({"ts": element.get("ts", 0), "data": element})

    async def pull(self, *args, **kwargs):
        raise RuntimeError("profile unreachable")


def _owner_link(owner_keys):
    return IdentityLink(
        v=2,
        owner_id=user_id_for(owner_keys["edPub"]),
        pseudo="owner",
        ed_pub=owner_keys["edPub"],
        kem_pub=owner_keys["kemPub"],
        kem_sig=sign_kem_sig(owner_keys["kemPub"], owner_keys["edPriv"]),
    )


async def test_submit_and_scan_round_trip(monkeypatch):
    inbox: dict = {}
    monkeypatch.setattr(spaces_client, "make_anon_space_client", lambda opts: FakeAnon(inbox))

    owner = make_fake_session()
    requester = make_fake_session()

    async def fake_pull(client, session, identity, shard, since=0):
        return inbox.get(session.layout.inbox_push(identity, shard), [])

    monkeypatch.setattr(rr, "pull_inbox", fake_pull)

    res = await submit_resource_request(
        requester, _owner_link(owner.keys),
        {"spaceId": "sp-1", "nodeType": "note", "title": "Hello"},
    )
    assert res["reqId"]

    pending = await scan_resource_requests(owner)
    assert len(pending) == 1
    assert pending[0]["senderEdPub"] == requester.keys["edPub"]
    assert pending[0]["req"]["title"] == "Hello"


async def test_scan_rejects_missing_added_by(monkeypatch):
    """Fail-closed: an element whose sealed entry has no addedBy is dropped."""
    owner = make_fake_session()
    requester = make_fake_session()

    request = {
        "v": 1,
        "kind": "create-resource",
        "reqId": "req-xyz",
        "spaceId": "sp-1",
        "nodeType": "note",
        "title": "Hi",
        "requester": {
            "userId": requester.user_id,
            "edPub": requester.keys["edPub"],
            "kemPub": requester.keys["kemPub"],
            "kemSig": sign_kem_sig(requester.keys["kemPub"], requester.keys["edPriv"]),
        },
    }

    # Unseal is faked to always yield the same request regardless of the blob,
    # isolating the scan-level addedBy authenticity gate.
    def fake_unseal(keys, sealed, aad=None):
        return json.dumps(request)

    monkeypatch.setattr(rr, "unseal_from_recipient", fake_unseal)

    def make_elem(added_by):
        entry = {"addedBy": added_by} if added_by is not None else {}
        return {"ts": 1, "data": {"sealed": {"entry": entry}, "ts": 1, "mkind": "request"}}

    good = make_elem(requester.keys["edPub"])
    missing = make_elem(None)

    async def fake_pull_missing(client, session, identity, shard, since=0):
        # only serve on the current shard to avoid duplicates
        from starfish_spaces.inbox import inbox_shard
        return [missing] if shard == inbox_shard() else []

    async def fake_pull_good(client, session, identity, shard, since=0):
        from starfish_spaces.inbox import inbox_shard
        return [good] if shard == inbox_shard() else []

    monkeypatch.setattr(rr, "pull_inbox", fake_pull_missing)
    assert await scan_resource_requests(owner) == []

    monkeypatch.setattr(rr, "pull_inbox", fake_pull_good)
    accepted = await scan_resource_requests(owner)
    assert len(accepted) == 1
    assert accepted[0]["req"]["reqId"] == "req-xyz"
