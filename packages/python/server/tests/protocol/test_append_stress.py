"""Stress tests characterizing append-only parse/serialize cost as a log grows.

The whole feature stores every element in ONE JSON blob per document, so every
append rewrites the blob and every pull parses it in full. These tests measure
that cost at increasing document sizes — they don't assert tight timings (those
flake across hardware); they print numbers and assert only generous ceilings so
a regression that turns linear into something pathological still trips, and a
hang can't run forever.

Opt-in only — every test is marked ``stress`` and the package's pytest config
excludes that marker by default (``addopts = -m 'not stress'``). Run them with::

    uv run pytest -v -s -m stress tests/protocol/test_append_stress.py

Layer: calls the protocol/router functions directly (no HTTP) to isolate the
document-parse cost from request/response overhead. Mirrors the TypeScript
``append-only.stress.test.ts`` suite.
"""

import json
import time

import pytest

from starfish_server.protocol.push import append_item, append_chunk_key, append_seg_prefix
from starfish_server.protocol.types import PushSuccess
from starfish_server.router.helpers import handle_append_only_pull
from tests.helpers import MemoryObjectStore

pytestmark = pytest.mark.stress

FIELD = "items"
SIZES = [1_000, 10_000, 50_000, 100_000]
PAYLOAD_SMALL = 8  # bytes of filler per element
PAYLOAD_LARGE = 1024  # ~1 KB per element


async def _seed(key: str, n: int, payload_bytes: int) -> MemoryObjectStore:
    """Store a document already holding ``n`` ``{ts, data}`` elements.

    ``ts`` runs 1..n (strictly increasing, so the pull-side bisect is valid) and
    ``data`` carries ``payload_bytes`` of filler. Append/pull never verify the
    stored ``hash``, so the placeholder below is fine — no recompute needed.
    """
    store = MemoryObjectStore()
    filler = "x" * payload_bytes
    items = [{"ts": i + 1, "data": {"v": filler}} for i in range(n)]
    doc = {"v": 1, "data": {FIELD: items}, "ts": n, "hash": ""}
    await store.put(key, json.dumps(doc), content_type="application/json")
    return store


async def _seed_chunked(key: str, n: int, payload_bytes: int, chunk_size: int) -> MemoryObjectStore:
    """Pre-seed a SEGMENTED document holding ``n`` elements directly (no sequential
    append — that would be O(n·chunk_size) to build). Writes ceil(n/chunk_size) chunk
    objects (each keyed by its first element's ``ts``) plus the head doc, mirroring
    what ``append_item(chunk_size=…)`` would produce."""
    store = MemoryObjectStore()
    filler = "x" * payload_bytes
    tail_key = ""
    for start in range(0, n, chunk_size):
        end = min(start + chunk_size, n)
        arr = [{"ts": i + 1, "data": {"v": filler}} for i in range(start, end)]
        tail_key = append_chunk_key(key, start + 1)  # firstTs of this chunk = start + 1
        await store.put(tail_key, json.dumps(arr), content_type="application/json")
    head = {"v": 1, "seg": True, "data": {}, "n": n, "ts": n, "hash": "", "chunkSize": chunk_size, "tailKey": tail_key}
    await store.put(key, json.dumps(head), content_type="application/json")
    return store


def _pulled_items(resp) -> list:
    return json.loads(resp.body)["data"][FIELD]


# Distinct document_key per case/N — the module-level _push_locks registry
# serialises by key, so sharing a key across tests would queue unrelated work.


@pytest.mark.parametrize("n", SIZES)
async def test_append_to_preseeded(n: int):
    """Append cost grows ~linearly with current size (=> O(n^2) to build)."""
    key = f"stress/append/{n}"
    store = await _seed(key, n, PAYLOAD_SMALL)
    t0 = time.perf_counter()
    out = await append_item(store, key, {"v": "appended"}, FIELD, n + 1)
    dt = time.perf_counter() - t0
    print(f"[append]            N={n:>9,} -> {dt * 1000:.2f} ms")
    assert isinstance(out, PushSuccess)
    assert out.timestamp == n + 1
    assert dt < 10.0


@pytest.mark.parametrize("n", SIZES)
async def test_full_pull_checkpoint_zero(n: int):
    """Full pull parses the whole blob — cost ~linear with size."""
    key = f"stress/fullpull/{n}"
    store = await _seed(key, n, PAYLOAD_SMALL)
    t0 = time.perf_counter()
    resp = await handle_append_only_pull(key, store, None, FIELD)
    dt = time.perf_counter() - t0
    items = _pulled_items(resp)
    print(f"[full-pull]         N={n:>9,} -> {dt * 1000:.2f} ms (returned {len(items):,})")
    assert len(items) == n
    assert dt < 30.0


@pytest.mark.parametrize("n", SIZES)
async def test_pull_checkpoint_at_tail(n: int):
    """Checkpoint-at-tail pull (~10 survivors) is still O(n).

    The checkpoint only trims what is RETURNED. Python's handler reads + parses
    the whole blob AND builds a full ``element_ts`` list (an extra O(n) pass)
    before ``bisect`` — so a tail query is no cheaper to parse than a full pull,
    and is strictly heavier than the TypeScript path, which bisects the parsed
    array directly. The printed numbers (compared with full-pull above and with
    the TS suite) make that divergence visible.
    """
    key = f"stress/checkpoint/{n}"
    store = await _seed(key, n, PAYLOAD_SMALL)
    checkpoint = str(n - 10)  # survivors: ts in (n-10 .. n] => 10 elements
    t0 = time.perf_counter()
    resp = await handle_append_only_pull(key, store, checkpoint, FIELD)
    dt = time.perf_counter() - t0
    items = _pulled_items(resp)
    print(f"[checkpoint-tail]   N={n:>9,} -> {dt * 1000:.2f} ms (returned {len(items):,})")
    assert len(items) == 10
    assert dt < 30.0


@pytest.mark.parametrize("n", [1_000, 5_000, 10_000])
async def test_sequential_build_quadratic(n: int):
    """Sequential build is quadratic — per-item append time climbs as it grows.

    Real-world shape: an app that appends forever without ever resetting the doc.
    Kept to <=10k items because total work is O(n^2).
    """
    key = f"stress/seqbuild/{n}"
    store = MemoryObjectStore()
    t0 = time.perf_counter()
    for i in range(n):
        await append_item(store, key, {"i": i}, FIELD, i + 1)
    dt = time.perf_counter() - t0
    print(f"[seq-build]         N={n:>9,} -> total {dt * 1000:.2f} ms, {dt / n * 1e6:.2f} us/item")
    doc = json.loads(await store.get_string(key))
    assert len(doc["data"][FIELD]) == n
    assert dt < 120.0  # O(n^2) build; generous ceiling — Python is ~3x slower than TS here


@pytest.mark.parametrize("n", [1_000, 5_000, 10_000])
async def test_chunked_build_is_linear(n: int):
    """Contrast with test_sequential_build_quadratic: with chunk_size an append
    touches only the open tail chunk, so per-item time stays bounded (no O(n²))."""
    chunk_size = 1_000
    key = f"stress/chunked-build/{n}"
    store = MemoryObjectStore()
    t0 = time.perf_counter()
    for i in range(n):
        await append_item(store, key, {"i": i}, FIELD, i + 1, chunk_size=chunk_size)
    dt = time.perf_counter() - t0
    print(f"[chunked-build]     N={n:>9,} -> total {dt * 1000:.2f} ms, {dt / n * 1e6:.2f} us/item")
    assert dt < 60.0


async def test_large_payload_100k():
    """Large payload @ 100k (~100 MB blob) — bytes drive cost, not just count."""
    key = "stress/large/100k"
    store = await _seed(key, 100_000, PAYLOAD_LARGE)

    t_a = time.perf_counter()
    out = await append_item(store, key, {"v": "x" * PAYLOAD_LARGE}, FIELD, 100_001)
    dt_append = time.perf_counter() - t_a

    t_p = time.perf_counter()
    resp = await handle_append_only_pull(key, store, None, FIELD)
    dt_pull = time.perf_counter() - t_p

    print(f"[large-100k ~100MB] append {dt_append * 1000:.2f} ms, full-pull {dt_pull * 1000:.2f} ms")
    assert isinstance(out, PushSuccess)
    assert out.timestamp == 100_001
    assert resp.status_code == 200
    assert dt_pull < 60.0


# ---------------------------------------------------------------------------
# Comprehensive characterization of the SEGMENTED (chunk_size) layout vs size.
# With chunking, append and tail-oriented pulls are bounded by chunk_size and stay
# ~flat as the total log grows, where the single-doc layout is O(n). Docs are
# pre-seeded directly (building 1M elements by sequential append would be slow).
# ---------------------------------------------------------------------------

_CHUNK = 10_000
_CHUNK_SIZES = [10_000, 100_000, 1_000_000]  # total element counts


@pytest.mark.parametrize("n", _CHUNK_SIZES)
async def test_chunked_append_flat_vs_n(n: int):
    """Append cost is ~flat vs N (bounded by chunk_size, not total size)."""
    key = f"cperf/append/{n}"
    store = await _seed_chunked(key, n, PAYLOAD_SMALL, _CHUNK)
    t0 = time.perf_counter()
    out = await append_item(store, key, {"v": "appended"}, FIELD, n + 1, chunk_size=_CHUNK)
    dt = time.perf_counter() - t0
    print(f"[chunk append]      N={n:>11,} cs={_CHUNK:,} -> {dt * 1000:.2f} ms")
    assert isinstance(out, PushSuccess)
    assert dt < 10.0


@pytest.mark.parametrize("n", _CHUNK_SIZES)
async def test_chunked_checkpoint_tail_flat_vs_n(n: int):
    """Checkpoint-tail pull is ~flat vs N (reads only the boundary chunk)."""
    key = f"cperf/cp/{n}"
    store = await _seed_chunked(key, n, PAYLOAD_SMALL, _CHUNK)
    total_chunks = len(await store.list_keys(append_seg_prefix(key)))
    t0 = time.perf_counter()
    resp = await handle_append_only_pull(key, store, str(n - 10), FIELD)
    dt = time.perf_counter() - t0
    items = _pulled_items(resp)
    print(f"[chunk cp-tail]     N={n:>11,} ({total_chunks:,} chunks) -> {dt * 1000:.2f} ms (returned {len(items)})")
    assert len(items) == 10
    assert dt < 10.0


@pytest.mark.parametrize("n", _CHUNK_SIZES)
async def test_chunked_last_flat_vs_n(n: int):
    """last=100 pull is ~flat vs N (reads only the final chunk)."""
    key = f"cperf/last/{n}"
    store = await _seed_chunked(key, n, PAYLOAD_SMALL, _CHUNK)
    t0 = time.perf_counter()
    resp = await handle_append_only_pull(key, store, None, FIELD, None, True, "100")
    dt = time.perf_counter() - t0
    print(f"[chunk last=100]    N={n:>11,} -> {dt * 1000:.2f} ms (returned {len(_pulled_items(resp))})")
    assert len(_pulled_items(resp)) == 100
    assert dt < 10.0


@pytest.mark.parametrize("n", _CHUNK_SIZES)
async def test_chunked_full_pull_grows_with_n(n: int):
    """Full pull grows with N (reads every chunk — returns everything)."""
    key = f"cperf/full/{n}"
    store = await _seed_chunked(key, n, PAYLOAD_SMALL, _CHUNK)
    t0 = time.perf_counter()
    resp = await handle_append_only_pull(key, store, None, FIELD)
    dt = time.perf_counter() - t0
    print(f"[chunk full-pull]   N={n:>11,} -> {dt * 1000:.2f} ms (returned {len(_pulled_items(resp)):,})")
    assert len(_pulled_items(resp)) == n
    assert dt < 60.0


@pytest.mark.parametrize("cs", [1_000, 10_000, 50_000])
async def test_chunk_size_sweep_at_100k(cs: int):
    """chunkSize sweep @ N=100k — append & checkpoint cost scale with chunk_size, not N."""
    n = 100_000
    key = f"cperf/sweep/{cs}"
    store = await _seed_chunked(key, n, PAYLOAD_SMALL, cs)
    t_a = time.perf_counter()
    await append_item(store, key, {"v": "appended"}, FIELD, n + 1, chunk_size=cs)
    dt_a = time.perf_counter() - t_a
    t_p = time.perf_counter()
    await handle_append_only_pull(key, store, str(n - 10), FIELD)
    dt_p = time.perf_counter() - t_p
    print(f"[chunk sweep]       N={n:,} cs={cs:>7,} -> append {dt_a * 1000:.2f} ms, cp-tail {dt_p * 1000:.2f} ms")


async def test_chunked_vs_single_doc_at_100k():
    """Side-by-side @ N=100k — chunked vs single-doc (append + checkpoint-tail)."""
    n = 100_000

    single = await _seed("cperf/cmp-single", n, PAYLOAD_SMALL)
    t = time.perf_counter()
    await append_item(single, "cperf/cmp-single", {"v": "x"}, FIELD, n + 1)
    s_append = time.perf_counter() - t
    t = time.perf_counter()
    await handle_append_only_pull("cperf/cmp-single", single, str(n - 10), FIELD)
    s_pull = time.perf_counter() - t

    chunked = await _seed_chunked("cperf/cmp-chunked", n, PAYLOAD_SMALL, _CHUNK)
    t = time.perf_counter()
    await append_item(chunked, "cperf/cmp-chunked", {"v": "x"}, FIELD, n + 1, chunk_size=_CHUNK)
    c_append = time.perf_counter() - t
    t = time.perf_counter()
    await handle_append_only_pull("cperf/cmp-chunked", chunked, str(n - 10), FIELD)
    c_pull = time.perf_counter() - t

    print(f"[cmp @100k] append:  single {s_append * 1000:.2f} ms  vs  chunked {c_append * 1000:.2f} ms")
    print(f"[cmp @100k] cp-tail: single {s_pull * 1000:.2f} ms  vs  chunked {c_pull * 1000:.2f} ms")
