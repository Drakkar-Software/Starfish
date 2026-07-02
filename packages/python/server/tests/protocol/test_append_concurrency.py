"""Cross-instance append safety via compare-and-swap (mirrors the TS
append-concurrency.test.ts).

append_item's in-process per-key lock serialises same-key writes within ONE
instance, but two server instances sharing one bucket both read-modify-write the
head with no coordination — the second silently drops the first's element.

When the store supports compare-and-swap (get_with_etag + put_if_match),
append_item writes the single-document head with an atomic CAS: on a detected
concurrent write it re-reads and retries rather than overwriting, and raises
AppendConcurrencyError if the contention never clears.
"""

import json

import pytest

from starfish_server.protocol.push import append_item, AppendConcurrencyError
from starfish_server.protocol.types import PushSuccess
from starfish_server.storage.memory import CustomObjectStore
from tests.helpers import MemoryObjectStore


class _CompetingWriterStore(MemoryObjectStore):
    """A CAS-capable store that simulates a competing instance committing an
    element right before our put_if_match runs."""

    def __init__(self, key: str, always: bool) -> None:
        super().__init__()
        self._key = key
        self._always = always
        self._count = 0

    async def put_if_match(
        self, key, body, expected_etag, *, content_type=None, cache_control=None, context=None
    ):
        if key == self._key and (self._always or self._count == 0):
            self._count += 1
            # A concurrent instance commits a distinct element first, changing the
            # head etag so our CAS (built from the pre-read etag) must fail.
            competitor = {
                "v": 1,
                "data": {"items": [{"ts": self._count, "data": {"who": "other", "n": self._count}}]},
                "ts": self._count,
                "hash": "competitor",
            }
            await self.put(key, json.dumps(competitor))
        return await super().put_if_match(
            key, body, expected_etag, content_type=content_type, cache_control=cache_control, context=context
        )


@pytest.mark.asyncio
async def test_retries_and_preserves_competing_element():
    store = _CompetingWriterStore("col/doc", always=False)

    out = await append_item(store, "col/doc", {"who": "me"}, "items", None)
    assert isinstance(out, PushSuccess)

    doc = json.loads(await store.get_string("col/doc"))
    # The competing element must survive AND our element is appended after it.
    assert len(doc["data"]["items"]) == 2
    assert doc["data"]["items"][0]["data"] == {"who": "other", "n": 1}
    assert doc["data"]["items"][1]["data"] == {"who": "me"}


@pytest.mark.asyncio
async def test_surfaces_conflict_when_contention_never_clears():
    store = _CompetingWriterStore("col/doc", always=True)

    with pytest.raises(AppendConcurrencyError):
        await append_item(store, "col/doc", {"who": "me"}, "items", None)


@pytest.mark.asyncio
async def test_store_without_cas_keeps_last_write_wins():
    """A store lacking get_with_etag/put_if_match uses the plain-put fallback."""
    data: dict[str, str] = {}
    store = CustomObjectStore(
        on_get=lambda key: data.get(key),
        on_put=lambda key, body: data.__setitem__(key, body),
    )
    out = await append_item(store, "col/doc", {"a": 1}, "items", None)
    assert isinstance(out, PushSuccess)
    doc = json.loads(data["col/doc"])
    assert len(doc["data"]["items"]) == 1
