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


def encode_parquet(rows: list[dict]) -> bytes:
    """Encode a list of flat event-row dicts as an Apache Parquet byte string.

    All values are coerced to :class:`str` so integers, floats, ``None``, and
    other JSON types are stored as strings rather than causing a type error.
    Missing keys default to ``""`` (empty string).

    :param rows: List of row dicts; each row is one SunGlasses event as
        flattened by the adapter's ``toStarfishRow`` (or an equivalent mapper).
    :returns: Raw Parquet bytes starting (and ending) with the ``PAR1`` magic.
    :raises Exception: Propagated from pyarrow on encoding failure; the plugin
        wraps this as an HTTP 500 so the client retries.
    """
    table = pa.table(
        {
            col: pa.array(
                [str(row[col]) if row.get(col) is not None else "" for row in rows],
                type=pa.string(),
            )
            for col in COLUMNS
        }
    )
    buf = io.BytesIO()
    pq.write_table(table, buf, compression="none")
    return buf.getvalue()
