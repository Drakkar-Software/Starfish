"""add_space_member / remove_space_member retry on CAS conflict."""

from __future__ import annotations

from types import SimpleNamespace

from starfish_sdk.types import ConflictError, StarfishHttpError

from starfish_spaces.registry import add_space_member, remove_space_member


class _Res:
    def __init__(self, data, hash_):
        self.data = data
        self.hash = hash_


class FakeAccessClient:
    """In-memory ``_access`` doc that conflicts on the first push, then converges."""

    def __init__(self, data, hash_, conflict_on, conflict_data=None):
        self.data = data
        self.hash = hash_
        self.conflict_on = set(conflict_on)
        self.conflict_data = conflict_data or {"owner": "owner", "members": ["intruder"]}
        self.push_calls = 0

    async def pull(self, path):
        if self.data is None:
            raise StarfishHttpError(404, "not found")
        return _Res(self.data, self.hash)

    async def push(self, path, payload, hash_):
        self.push_calls += 1
        if self.push_calls in self.conflict_on:
            # Someone else wrote under us: server advances to a new hash/state.
            self.data = dict(self.conflict_data)
            self.hash = "h-conflict"
            raise ConflictError()
        self.data = payload
        self.hash = f"h-ok-{self.push_calls}"


def _session():
    from starfish_spaces.layout import default_space_layout
    return SimpleNamespace(layout=default_space_layout)


async def test_add_space_member_retries_stale_hash():
    client = FakeAccessClient(
        {"owner": "owner", "members": []}, "h0", conflict_on={1},
    )
    await add_space_member(client, "sp-1", "owner", "newmember", _session())

    assert client.push_calls == 2  # first push conflicted, retried
    # Final state merges the concurrent write with our addition.
    assert set(client.data["members"]) == {"intruder", "newmember"}


async def test_remove_space_member_retries_stale_hash():
    client = FakeAccessClient(
        {"owner": "owner", "members": ["victim"]}, "h0", conflict_on={1},
        conflict_data={"owner": "owner", "members": ["victim", "intruder"]},
    )
    await remove_space_member(client, "sp-1", "victim", _session())

    assert client.push_calls == 2  # first push conflicted, retried
    # The victim is removed from the merged (post-conflict) roster.
    assert "victim" not in client.data["members"]
    assert "intruder" in client.data["members"]


async def test_add_space_member_noop_when_present():
    client = FakeAccessClient(
        {"owner": "owner", "members": ["already"]}, "h0", conflict_on=set(),
    )
    await add_space_member(client, "sp-1", "owner", "already", _session())
    assert client.push_calls == 0
