"""Tests for make_issuer_bound_role_enricher.

Mirror of TS ``tests/issuer-bound-role-enricher.test.ts``.
"""

from starfish_server.router.route_builder import AuthResult
from starfish_sharing import make_issuer_bound_role_enricher

OWNER = "pubspace:owner"
READER = "pubspace:reader"
WRITER = "pubspace:writer"


def _enricher():
    return make_issuer_bound_role_enricher(
        owner_param="ownerId",
        owner_role=OWNER,
        reader_role=READER,
        writer_role=WRITER,
        collections=["pubspace", "pubstream"],
        guard_param="docId",
        guard_value="_rooms",
    )


def _auth(identity: str, roles: list[str]) -> AuthResult:
    return AuthResult(identity=identity, roles=roles)


async def test_owner_gets_owner_and_reader():
    roles = await _enricher()(_auth("alice", []), {"ownerId": "alice", "docId": "room-1"})
    assert roles == [OWNER, READER]


async def test_delegated_by_owner_gets_reader():
    auth = _auth("bob", ["delegated:alice:pubspace"])
    roles = await _enricher()(auth, {"ownerId": "alice", "docId": "room-1"})
    assert roles == [READER]


async def test_delegated_with_write_on_non_guard_doc_gets_writer():
    auth = _auth("bob", ["delegated:alice:pubspace", "cap:write:pubspace"])
    roles = await _enricher()(auth, {"ownerId": "alice", "docId": "room-1"})
    assert roles == [READER, WRITER]


async def test_delegated_with_write_on_guard_doc_no_writer():
    auth = _auth("bob", ["delegated:alice:pubspace", "cap:write:pubspace"])
    roles = await _enricher()(auth, {"ownerId": "alice", "docId": "_rooms"})
    assert roles == [READER]


async def test_unrelated_issuer_gets_nothing():
    # Delegated by a DIFFERENT owner than the path owner.
    auth = _auth("bob", ["delegated:carol:pubspace", "cap:write:pubspace"])
    roles = await _enricher()(auth, {"ownerId": "alice", "docId": "room-1"})
    assert roles == []


async def test_alt_collection_delegation_admitted():
    auth = _auth("bob", ["delegated:alice:pubstream", "cap:write:pubstream"])
    roles = await _enricher()(auth, {"ownerId": "alice", "docId": "room-1"})
    assert roles == [READER, WRITER]


async def test_missing_owner_param():
    roles = await _enricher()(_auth("alice", []), {"docId": "room-1"})
    assert roles == []


async def test_empty_identity():
    roles = await _enricher()(_auth("", []), {"ownerId": "alice", "docId": "room-1"})
    assert roles == []
