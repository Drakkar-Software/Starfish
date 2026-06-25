"""Unit tests for encode_parquet — the low-level Parquet encoder.

Tests cover: schema correctness, PAR1 magic, value coercion, missing fields,
empty batches, large batches, and special characters.  Each test decodes the
Parquet bytes with pyarrow to verify logical correctness.
"""

from __future__ import annotations

import io

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from starfish_events.encode import COLUMNS, encode_parquet


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def decode(parquet_bytes: bytes) -> list[dict]:
    """Decode Parquet bytes to a list of row dicts using pyarrow."""
    table = pq.read_table(io.BytesIO(parquet_bytes))
    return table.to_pydict()  # column-name → list-of-values mapping


def schema_names(parquet_bytes: bytes) -> list[str]:
    """Return ordered column names from the Parquet file schema."""
    return pq.read_schema(io.BytesIO(parquet_bytes)).names


_SAMPLE_ROW = {
    "event_type": "capture",
    "event": "button_clicked",
    "distinct_id": "user-abc",
    "anonymous_id": "anon-xyz",
    "ts": "2024-06-01T10:00:00.000Z",
    "message_id": "msg-001",
    "properties": '{"label":"Submit"}',
    "context": '{"platform":"web"}',
    "dt": "2024-06-01",
    "received_at": "2024-06-01T10:00:01.000Z",
}


# ---------------------------------------------------------------------------
# PAR1 magic
# ---------------------------------------------------------------------------


def test_encode_produces_valid_parquet_magic_start():
    data = encode_parquet([_SAMPLE_ROW])
    assert data[:4] == b"PAR1", "Parquet files must start with PAR1 magic"


def test_encode_produces_valid_parquet_magic_end():
    data = encode_parquet([_SAMPLE_ROW])
    assert data[-4:] == b"PAR1", "Parquet files must end with PAR1 magic"


def test_encode_returns_bytes_not_bytearray():
    data = encode_parquet([_SAMPLE_ROW])
    assert isinstance(data, bytes), "encode_parquet must return bytes, not bytearray or memoryview"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_encode_schema_has_all_ten_columns():
    data = encode_parquet([_SAMPLE_ROW])
    assert schema_names(data) == list(COLUMNS)


def test_encode_column_order_is_fixed():
    """Column order must match the COLUMNS tuple exactly (part of the DuckDB contract)."""
    data = encode_parquet([_SAMPLE_ROW])
    assert schema_names(data) == list(COLUMNS)


def test_encode_all_columns_are_string_type():
    data = encode_parquet([_SAMPLE_ROW])
    schema = pq.read_schema(io.BytesIO(data))
    for field in schema:
        assert pa.types.is_string(field.type) or pa.types.is_large_string(field.type), (
            f"Column '{field.name}' should be STRING type, got {field.type}"
        )


# ---------------------------------------------------------------------------
# Correctness
# ---------------------------------------------------------------------------


def test_encode_single_row_roundtrip():
    data = encode_parquet([_SAMPLE_ROW])
    columns = decode(data)
    assert columns["event"] == ["button_clicked"]
    assert columns["event_type"] == ["capture"]
    assert columns["distinct_id"] == ["user-abc"]
    assert columns["anonymous_id"] == ["anon-xyz"]
    assert columns["ts"] == ["2024-06-01T10:00:00.000Z"]
    assert columns["message_id"] == ["msg-001"]
    assert columns["properties"] == ['{"label":"Submit"}']
    assert columns["context"] == ['{"platform":"web"}']
    assert columns["dt"] == ["2024-06-01"]
    assert columns["received_at"] == ["2024-06-01T10:00:01.000Z"]


def test_encode_multiple_rows_all_preserved_in_order():
    rows = [
        {**_SAMPLE_ROW, "message_id": "msg-001", "event": "page_viewed"},
        {**_SAMPLE_ROW, "message_id": "msg-002", "event": "button_clicked"},
        {**_SAMPLE_ROW, "message_id": "msg-003", "event": "form_submitted"},
    ]
    data = encode_parquet(rows)
    cols = decode(data)
    assert cols["event"] == ["page_viewed", "button_clicked", "form_submitted"]
    assert cols["message_id"] == ["msg-001", "msg-002", "msg-003"]


# ---------------------------------------------------------------------------
# Missing / None values
# ---------------------------------------------------------------------------


def test_encode_missing_field_defaults_to_empty_string():
    data = encode_parquet([{"event": "click"}])  # all other columns absent
    cols = decode(data)
    assert cols["event"] == ["click"]
    assert cols["event_type"] == [""]
    assert cols["distinct_id"] == [""]
    assert cols["received_at"] == [""]


def test_encode_none_value_becomes_empty_string():
    row = {**_SAMPLE_ROW, "distinct_id": None, "properties": None}
    data = encode_parquet([row])
    cols = decode(data)
    assert cols["distinct_id"] == [""]
    assert cols["properties"] == [""]


def test_encode_integer_value_coerced_to_string():
    row = {**_SAMPLE_ROW, "ts": 1717228800, "message_id": 42}
    data = encode_parquet([row])
    cols = decode(data)
    assert cols["ts"] == ["1717228800"]
    assert cols["message_id"] == ["42"]


# ---------------------------------------------------------------------------
# Empty batch
# ---------------------------------------------------------------------------


def test_encode_empty_rows_produces_valid_parquet():
    data = encode_parquet([])
    assert data[:4] == b"PAR1"
    assert data[-4:] == b"PAR1"


def test_encode_empty_rows_has_correct_schema():
    data = encode_parquet([])
    assert schema_names(data) == list(COLUMNS)


def test_encode_empty_rows_has_zero_rows():
    data = encode_parquet([])
    table = pq.read_table(io.BytesIO(data))
    assert table.num_rows == 0


# ---------------------------------------------------------------------------
# Special characters
# ---------------------------------------------------------------------------


def test_encode_unicode_and_emoji_in_strings():
    row = {**_SAMPLE_ROW, "event": "🎉 celebration — héros", "properties": '{"name":"André Ø"}'}
    data = encode_parquet([row])
    cols = decode(data)
    assert cols["event"] == ["🎉 celebration — héros"]
    assert cols["properties"] == ['{"name":"André Ø"}']


def test_encode_newlines_in_values():
    row = {**_SAMPLE_ROW, "properties": '{"msg":"line1\\nline2"}'}
    data = encode_parquet([row])
    cols = decode(data)
    assert "\\n" in cols["properties"][0] or "\n" in cols["properties"][0]


def test_encode_json_string_in_properties_preserved_verbatim():
    """Properties are opaque JSON strings — not parsed, not re-encoded."""
    payload = '{"nested":{"a":1},"arr":[1,2,3]}'
    row = {**_SAMPLE_ROW, "properties": payload}
    data = encode_parquet([row])
    assert decode(data)["properties"] == [payload]


# ---------------------------------------------------------------------------
# Large batch
# ---------------------------------------------------------------------------


def test_encode_large_batch_no_crash():
    """1 000 rows — no MemoryError, no encoding failure."""
    rows = [{**_SAMPLE_ROW, "message_id": f"msg-{i}", "event": f"event_{i}"} for i in range(1_000)]
    data = encode_parquet(rows)
    assert data[:4] == b"PAR1"
    table = pq.read_table(io.BytesIO(data))
    assert table.num_rows == 1_000
