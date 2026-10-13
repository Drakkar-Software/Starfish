"""Tests for starfish_sdk.events — SSE frame parser and subscribe_changes."""

import asyncio
import gc

import httpx
import pytest

from starfish_sdk.events import parse_sse_frames, subscribe_changes

_FRAME = 'data: {"n":1}\n\n'
_FRAME_2 = 'data: {"n":2}\n\n'
_URL = "https://events.test/stream"


def _patch_sleep(monkeypatch) -> list[int]:
    delays: list[int] = []

    async def fake_sleep(seconds: float) -> None:
        delays.append(int(round(seconds * 1000)))

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return delays


def _scripted_client(steps: list) -> tuple[httpx.AsyncClient, list[str]]:
    """MockTransport client that plays `steps` (Response or exception) in order."""
    index = {"i": 0}
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        step = steps[index["i"]]
        index["i"] += 1
        if isinstance(step, Exception):
            raise step
        return step

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client, urls


def _ok(body: str = _FRAME) -> httpx.Response:
    return httpx.Response(200, text=body)


def _status(code: int) -> httpx.Response:
    return httpx.Response(code, text="")


def _connect_error(message: str) -> httpx.ConnectError:
    return httpx.ConnectError(message)


# ── parse_sse_frames ──────────────────────────────────────────────────────────

def test_single_complete_frame():
    frames, carry = parse_sse_frames('data: {"x":1}\n\n', "")
    assert frames == [{"x": 1}]
    assert carry == ""


def test_incomplete_frame_no_blank_line():
    frames, carry = parse_sse_frames('data: {"x":1}\n', "")
    assert frames == []
    assert carry == 'data: {"x":1}\n'


def test_carry_split_across_two_chunks():
    frames1, carry1 = parse_sse_frames('data: {"x":', "")
    assert frames1 == []
    assert carry1 == 'data: {"x":'

    frames2, carry2 = parse_sse_frames('1}\n\n', carry1)
    assert frames2 == [{"x": 1}]
    assert carry2 == ""


def test_comment_lines_are_skipped():
    frames, carry = parse_sse_frames(': this is a comment\ndata: {"ok":true}\n\n', "")
    assert frames == [{"ok": True}]


def test_id_and_event_lines_ignored():
    chunk = "id: 42\nevent: update\ndata: {\"v\":7}\n\n"
    frames, _ = parse_sse_frames(chunk, "")
    assert frames == [{"v": 7}]


def test_multi_line_data_joined():
    # Two data: lines within one frame → values joined with \n; result must be
    # valid JSON after joining. We test the join mechanics with a raw string first.
    chunk = 'data: {"a":\ndata: 1}\n\n'
    frames, _ = parse_sse_frames(chunk, "")
    # '{"a":\n1}' is valid JSON (newline inside is fine for json.loads)
    assert frames == [{"a": 1}]


def test_multiple_frames_in_one_chunk():
    chunk = 'data: {"n":1}\n\ndata: {"n":2}\n\n'
    frames, carry = parse_sse_frames(chunk, "")
    assert frames == [{"n": 1}, {"n": 2}]
    assert carry == ""


def test_crlf_normalisation():
    chunk = "data: {\"x\":3}\r\n\r\n"
    frames, carry = parse_sse_frames(chunk, "")
    assert frames == [{"x": 3}]
    assert carry == ""


def test_retry_line_ignored():
    chunk = "retry: 1000\ndata: {\"a\":1}\n\n"
    frames, _ = parse_sse_frames(chunk, "")
    assert frames == [{"a": 1}]


def test_non_json_data_skipped():
    chunk = "data: not-json\n\n"
    frames, carry = parse_sse_frames(chunk, "")
    assert frames == []
    assert carry == ""


def test_empty_chunk_no_frames():
    frames, carry = parse_sse_frames("", "")
    assert frames == []
    assert carry == ""


def test_data_line_strips_exactly_one_leading_space():
    # WHATWG SSE §9.2.6: remove exactly ONE leading space after "data:" (parity
    # with the TypeScript parser). json.loads tolerates any residual leading
    # whitespace, so the parsed dict is identical either way — this pins the
    # spec-compliant extraction so a switch to str.strip()/lstrip() (which would
    # also eat a tab or extra spaces) does not silently diverge from TS.
    one_space, _ = parse_sse_frames('data: {"v": 1}\n\n', "")
    two_spaces, _ = parse_sse_frames('data:  {"v": 1}\n\n', "")
    assert one_space == [{"v": 1}]
    assert two_spaces == [{"v": 1}]


def test_data_line_preserves_leading_tab():
    # Only a leading SPACE is stripped; a tab is part of the payload.
    frames, _ = parse_sse_frames('data:\t{"v": 2}\n\n', "")
    assert frames == [{"v": 2}]


def test_carry_preserved_across_comment_and_data():
    # First chunk: comment only — no frame yet
    frames1, carry1 = parse_sse_frames(": keep-alive\n", "")
    assert frames1 == []

    # Second chunk: data + blank line completes frame
    frames2, carry2 = parse_sse_frames('data: {"z":9}\n\n', carry1)
    assert frames2 == [{"z": 9}]
    assert carry2 == ""


# ── subscribe_changes ─────────────────────────────────────────────────────────


async def _first_frame(**kwargs) -> dict:
    kwargs.setdefault("initial_backoff_ms", 10)
    kwargs.setdefault("max_backoff_ms", 40)
    gen = subscribe_changes(**kwargs)
    frame = await gen.__anext__()
    await gen.aclose()
    return frame


async def test_subscribe_reconnects_after_connect_error(monkeypatch):
    # T1: two network errors, then one frame. on_status sees only the 200.
    _patch_sleep(monkeypatch)
    statuses: list[int] = []
    client, _urls = _scripted_client([
        _connect_error("down"),
        _connect_error("down"),
        _ok(),
    ])
    frame = await _first_frame(
        url=_URL,
        session=client,
        on_status=statuses.append,
    )
    assert frame == {"n": 1}
    assert statuses == [200]
    await client.aclose()


async def test_subscribe_backoff_doubles_and_caps(monkeypatch):
    # T2: five failures then a frame. Delays double and stick at the cap.
    delays = _patch_sleep(monkeypatch)
    client, _urls = _scripted_client([_connect_error("down")] * 5 + [_ok()])
    frame = await _first_frame(url=_URL, session=client)
    assert frame == {"n": 1}
    assert delays == [10, 20, 40, 40, 40]
    await client.aclose()


async def test_subscribe_backoff_resets_after_successful_connect(monkeypatch):
    # T3: errors at 10 then 20, a clean 200, then the next delay is the reset 10.
    delays = _patch_sleep(monkeypatch)
    client, _urls = _scripted_client([
        _connect_error("down"),
        _connect_error("down"),
        _ok(),
        _connect_error("down"),
        _ok(_FRAME_2),
    ])
    gen = subscribe_changes(
        url=_URL,
        session=client,
        initial_backoff_ms=10,
        max_backoff_ms=40,
    )
    frames = []
    async for frame in gen:
        frames.append(frame)
        if len(frames) == 2:
            break
    assert frames == [{"n": 1}, {"n": 2}]
    assert delays[:3] == [10, 20, 10]
    await client.aclose()


async def test_subscribe_retries_non_2xx_without_yielding(monkeypatch):
    # T4: 503 and 500 are not yielded. Only the following 200 frame is.
    delays = _patch_sleep(monkeypatch)
    client, _urls = _scripted_client([_status(503), _status(500), _ok()])
    frame = await _first_frame(url=_URL, session=client)
    assert frame == {"n": 1}
    assert delays == [10, 20]
    await client.aclose()


async def test_subscribe_on_status_called_before_backoff(monkeypatch):
    # T5: on_status runs for every attempt, before that attempt's backoff sleep.
    log: list[tuple] = []

    async def fake_sleep(seconds: float) -> None:
        log.append(("sleep", int(round(seconds * 1000))))

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    client, _urls = _scripted_client([_status(503), _status(500), _ok()])

    def on_status(code: int) -> None:
        log.append(("status", code))

    frame = await _first_frame(url=_URL, session=client, on_status=on_status)
    assert frame == {"n": 1}
    assert log == [
        ("status", 503),
        ("sleep", 10),
        ("status", 500),
        ("sleep", 20),
        ("status", 200),
    ]
    await client.aclose()


async def test_subscribe_reresolves_callable_url(monkeypatch):
    # T6: the URL factory is called again on every attempt.
    _patch_sleep(monkeypatch)
    planned = [
        "https://events.test/u1",
        "https://events.test/u2",
        "https://events.test/u3",
    ]
    produced: list[str] = []

    def factory() -> str:
        nxt = planned[len(produced)]
        produced.append(nxt)
        return nxt

    client, requested = _scripted_client([
        _connect_error("down"),
        _connect_error("down"),
        _ok(),
    ])
    frame = await _first_frame(url=factory, session=client)
    assert frame == {"n": 1}
    assert requested == planned
    await client.aclose()


def _patch_owned_client(monkeypatch) -> list[httpx.AsyncClient]:
    created: list[httpx.AsyncClient] = []
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda request: _ok())
        client = real(*args, **kwargs)
        created.append(client)
        return client

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return created


async def test_subscribe_closes_owned_client_on_aclose(monkeypatch):
    # T7: with no caller session, aclose() closes the client this call opened.
    created = _patch_owned_client(monkeypatch)
    gen = subscribe_changes(url=_URL, initial_backoff_ms=10, max_backoff_ms=40)
    frame = await gen.__anext__()
    assert frame == {"n": 1}
    await gen.aclose()
    assert len(created) == 1
    assert created[0].is_closed


async def test_subscribe_leaves_caller_session_open():
    # T8: a session passed by the caller stays open after the generator closes.
    client, _urls = _scripted_client([_ok()])
    gen = subscribe_changes(
        url=_URL,
        session=client,
        initial_backoff_ms=10,
        max_backoff_ms=40,
    )
    frame = await gen.__anext__()
    assert frame == {"n": 1}
    await gen.aclose()
    assert client.is_closed is False
    await client.aclose()


async def test_subscribe_break_closes_owned_client(monkeypatch):
    # T9: breaking out of async for closes the owned client.
    # CPython 3.12 does not aclose the generator inside the loop frame. The
    # close is scheduled once that frame is collected, so leave the loop in a
    # nested coroutine and wait for the finalizer task.
    created = _patch_owned_client(monkeypatch)

    async def consume() -> None:
        async for frame in subscribe_changes(
            url=_URL,
            initial_backoff_ms=10,
            max_backoff_ms=40,
        ):
            assert frame == {"n": 1}
            break

    await consume()
    gc.collect()
    await asyncio.sleep(0)
    pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
    if pending:
        await asyncio.gather(*pending)
    assert len(created) == 1
    assert created[0].is_closed


async def test_subscribe_retries_url_factory_and_propagates_on_status(monkeypatch):
    # T10 (option C): a URL-factory RuntimeError is retried; on_status raises.
    delays = _patch_sleep(monkeypatch)
    calls = {"n": 0}

    def factory() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("token refresh failed")
        return _URL

    client, _urls = _scripted_client([_ok()])
    frame = await _first_frame(url=factory, session=client)
    assert frame == {"n": 1}
    assert calls["n"] == 2
    assert delays == [10]

    def on_status(_code: int) -> None:
        raise RuntimeError("on_status bug")

    client2, _urls = _scripted_client([_ok()])
    gen = subscribe_changes(
        url=_URL,
        session=client2,
        on_status=on_status,
        initial_backoff_ms=10,
        max_backoff_ms=40,
    )
    with pytest.raises(RuntimeError, match="on_status bug"):
        await gen.__anext__()
    assert delays == [10]
    await client.aclose()
    await client2.aclose()
