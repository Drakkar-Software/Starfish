"""Cross-language protocol tests using shared test vectors."""

import json
from pathlib import Path

import pytest

from starfish_server.protocol.push import push
from starfish_server.protocol.pull import pull
from starfish_server.protocol.timestamps import compute_timestamps, filter_by_checkpoint
from starfish_server.storage.memory import MemoryObjectStore

VECTORS_DIR = Path(__file__).resolve().parents[5] / "tests" / "test-vectors"

PUSH_VECTORS = json.loads((VECTORS_DIR / "protocol-push.json").read_text())
TS_VECTORS = json.loads((VECTORS_DIR / "protocol-timestamps.json").read_text())


# --- Push conflict vectors ---

@pytest.mark.parametrize(
    "scenario",
    PUSH_VECTORS["pushConflict"],
    ids=lambda s: s["description"],
)
async def test_push_conflict(scenario):
    store = MemoryObjectStore(data={})
    last_hash = None
    for step in scenario["steps"]:
        base_hash = last_hash if step["baseHash"] == "$previous.hash" else step["baseHash"]
        result = await push(store, scenario["documentKey"], step["data"], base_hash)
        if step["expect"]["type"] == "success":
            assert hasattr(result, "hash")
            last_hash = result.hash
        else:
            assert hasattr(result, "error")
            assert result.error == step["expect"]["error"]


# --- Push success vectors ---

@pytest.mark.parametrize(
    "scenario",
    PUSH_VECTORS["pushSuccess"],
    ids=lambda s: s["description"],
)
async def test_push_success(scenario):
    store = MemoryObjectStore(data={})
    last_hash = None
    for step in scenario["steps"]:
        base_hash = last_hash if step["baseHash"] == "$previous.hash" else step["baseHash"]
        result = await push(store, scenario["documentKey"], step["data"], base_hash)
        if step["expect"]["type"] == "success":
            assert hasattr(result, "hash")
            if "hashLength" in step["expect"]:
                assert len(result.hash) == step["expect"]["hashLength"]
            last_hash = result.hash


# --- Push then pull vectors ---

@pytest.mark.parametrize(
    "scenario",
    PUSH_VECTORS["pushThenPull"],
    ids=lambda s: s["description"],
)
async def test_push_then_pull(scenario):
    store = MemoryObjectStore(data={})
    last_hash = None
    for step in scenario["steps"]:
        if step["action"] == "push":
            base_hash = last_hash if step["baseHash"] == "$previous.hash" else step["baseHash"]
            result = await push(store, scenario["documentKey"], step["data"], base_hash)
            if step["expect"]["type"] == "success":
                assert hasattr(result, "hash")
                last_hash = result.hash
        elif step["action"] == "pull":
            result = await pull(store, scenario["documentKey"], step.get("checkpoint", 0))
            if "data" in step["expect"]:
                assert result.data == step["expect"]["data"]
            if "hashLength" in step["expect"]:
                assert len(result.hash) == step["expect"]["hashLength"]


# --- Timestamp computation vectors ---

@pytest.mark.parametrize(
    "scenario",
    TS_VECTORS["computeTimestamps"],
    ids=lambda s: s["description"],
)
def test_compute_timestamps(scenario):
    result = compute_timestamps(
        scenario["oldData"],
        scenario["newData"],
        scenario["oldTimestamps"],
        scenario["now"],
    )
    assert result == scenario["expected"]


# --- Checkpoint filter vectors ---

@pytest.mark.parametrize(
    "scenario",
    TS_VECTORS["filterByCheckpoint"],
    ids=lambda s: s["description"],
)
def test_filter_by_checkpoint(scenario):
    result = filter_by_checkpoint(
        scenario["data"],
        scenario["timestamps"],
        scenario["checkpoint"],
    )
    assert result == scenario["expected"]
