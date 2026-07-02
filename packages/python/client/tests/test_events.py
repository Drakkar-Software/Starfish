"""Tests for starfish_sdk.events — SSE frame parser."""

import pytest

from starfish_sdk.events import parse_sse_frames


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
