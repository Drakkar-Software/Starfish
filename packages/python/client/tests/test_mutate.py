"""mutate_doc — hash-CAS read-modify-write with conflict retry, 404-as-absent,
and no-op skipping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import pytest

from starfish_sdk.mutate import DocState, mutate_doc
from starfish_sdk.types import ConflictError, StarfishHttpError


@dataclass
class _Pull:
    data: dict[str, Any]
    hash: str


class _FakeClient:
    """Duck-typed stand-in: mutate_doc only calls .pull() and .push()."""

    def __init__(self, *, pull, push=None):
        self._pull = pull
        self._push = push or (lambda path, data, base_hash: {"hash": "ok"})
        self.pull_calls: list[str] = []
        self.push_calls: list[tuple[str, dict, Optional[str]]] = []

    async def pull(self, path: str):
        self.pull_calls.append(path)
        return self._pull(path)

    async def push(self, path: str, data: dict, base_hash: Optional[str]):
        self.push_calls.append((path, data, base_hash))
        return self._push(path, data, base_hash)


async def test_pull_mutate_push_with_read_hash() -> None:
    client = _FakeClient(pull=lambda p: _Pull(data={"n": 1}, hash="h1"))
    out = await mutate_doc(client, "/doc", lambda cur: {"n": (cur.data or {}).get("n", 0) + 1})
    assert out == {"n": 2}
    assert len(client.push_calls) == 1
    assert client.push_calls[0][2] == "h1"
    assert client.push_calls[0][1] == {"n": 2}


async def test_retries_on_conflict_against_fresh_state() -> None:
    state = {"n": 10, "hash": "h10"}
    pushes = {"count": 0}

    def pull(_p):
        return _Pull(data={"n": state["n"]}, hash=state["hash"])

    def push(_p, _data, _base):
        pushes["count"] += 1
        if pushes["count"] == 1:
            state["n"] = 20
            state["hash"] = "h20"
            raise ConflictError()
        return {"hash": "ok"}

    client = _FakeClient(pull=pull, push=push)
    out = await mutate_doc(client, "/doc", lambda cur: {"n": (cur.data or {}).get("n", 0) + 1})
    assert out == {"n": 21}
    assert len(client.pull_calls) == 2


async def test_404_is_absent_document() -> None:
    def pull(_p):
        raise StarfishHttpError(404, "not found")

    client = _FakeClient(pull=pull)

    def mutator(cur: DocState):
        assert cur.data is None
        assert cur.hash is None
        return {"created": True}

    out = await mutate_doc(client, "/doc", mutator)
    assert out == {"created": True}
    assert client.push_calls[0][2] is None


async def test_no_op_skips_write() -> None:
    client = _FakeClient(pull=lambda p: _Pull(data={"n": 1}, hash="h1"))
    out = await mutate_doc(client, "/doc", lambda cur: None)
    assert out is None
    assert len(client.push_calls) == 0


async def test_persistent_conflict_propagates() -> None:
    def push(_p, _data, _base):
        raise ConflictError()

    client = _FakeClient(pull=lambda p: _Pull(data={}, hash="h"), push=push)
    with pytest.raises(ConflictError):
        await mutate_doc(client, "/doc", lambda cur: {"x": 1}, max_attempts=2)
    assert len(client.push_calls) == 2


async def test_non_conflict_pull_error_propagates() -> None:
    def pull(_p):
        raise StarfishHttpError(500, "boom")

    client = _FakeClient(pull=pull)
    with pytest.raises(StarfishHttpError):
        await mutate_doc(client, "/doc", lambda cur: {"x": 1})
