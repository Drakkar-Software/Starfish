"""Parquet encoding for SunGlasses event rows.

Column schema matches the ``EventRow`` produced by ``apps/ingest-server/src/schema.ts``
so DuckDB queries are identical regardless of which backend delivered the data
(HTTP ingest server vs. this Starfish-events plugin).

All columns are STRING (VARCHAR in Parquet terms).  ``UNCOMPRESSED`` codec
avoids a native/WASM compressor dependency and matches the TypeScript side
(``packages/ts/events/src/encode.ts``).

Privacy: the caller is responsible for never logging the contents of
``distinct_id``, ``properties``, or ``context``.  This module stores whatever
it receives opaquely.
"""
from __future__ import annotations

import io
import json

import pyarrow as pa
import pyarrow.parquet as pq

# Fixed column order — mirrors apps/ingest-server EventRow and
# packages/ts/events/src/encode.ts.  The order is part of the schema contract
# consumed by DuckDB; do not reorder.
COLUMNS: tuple[str, ...] = (
    "event_type",
    "event",
    "distinct_id",
    "anonymous_id",
    "ts",
    "message_id",
    "properties",
    "context",
    "dt",
    "received_at",
)


def _coerce_cell(value: object) -> str:
    """Coerce one cell value to the canonical string stored in Parquet.

    ``None`` becomes ``""``; strings pass through verbatim; every other JSON
    value (dict, list, int, float, bool) is serialized as compact JSON with
    recursively-sorted keys.  This must stay identical to the TypeScript encoder
    (``JSON.stringify`` over recursively key-sorted values) so DuckDB sees the
    same strings regardless of which backend produced the file.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def encode_parquet(rows: list[dict]) -> bytes:
    """Encode a list of flat event-row dicts as an Apache Parquet byte string.

    All values are coerced to :class:`str`: strings pass through verbatim,
    ``None`` and missing keys become ``""`` (empty string), and every other
    JSON value (dict, list, int, float, bool) is serialized as compact,
    key-sorted JSON — matching the TypeScript encoder so both backends store
    identical strings.

    :param rows: List of row dicts; each row is one SunGlasses event as
        flattened by the adapter's ``toStarfishRow`` (or an equivalent mapper).
    :returns: Raw Parquet bytes starting (and ending) with the ``PAR1`` magic.
    :raises Exception: Propagated from pyarrow on encoding failure; the plugin
        wraps this as an HTTP 500 so the client retries.
    """
    table = pa.table(
        {
            col: pa.array(
                [_coerce_cell(row.get(col)) for row in rows],
                type=pa.string(),
            )
            for col in COLUMNS
        }
    )
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="none")
    return buf.getvalue()
