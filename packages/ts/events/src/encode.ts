/**
 * Parquet encoding for SunGlasses event rows.
 *
 * Column schema matches the EventRow produced by `apps/ingest-server/src/schema.ts`
 * so DuckDB queries are identical regardless of which backend delivered the data.
 *
 * All columns are VARCHAR (STRING) — properties and context are opaque JSON strings.
 * UNCOMPRESSED codec avoids a native/WASM compressor dependency.
 */
import { parquetWriteBuffer } from "hyparquet-writer"

/** Column names in fixed order — mirrors apps/ingest-server EventRow. */
const COLUMNS = [
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
] as const

type ColumnName = (typeof COLUMNS)[number]

/**
 * Encode an array of flat event row objects as a Parquet-format `Uint8Array`.
 *
 * Missing fields default to empty string. All values are stored as STRING
 * (VARCHAR-equivalent in Parquet). `received_at` should be an ISO-8601 UTC
 * timestamp stamped by the plugin at ingest time.
 *
 * Privacy: caller is responsible for never passing distinct_id/properties/
 * context to logs; this function stores whatever it receives opaquely.
 */
export function encodeParquet(rows: Record<string, unknown>[]): Uint8Array {
  const columnData = COLUMNS.map((name: ColumnName) => ({
    name,
    type: "STRING" as const,
    nullable: false,
    data: rows.map((r) => String(r[name] ?? "")),
  }))

  const buffer = parquetWriteBuffer({ columnData, codec: "UNCOMPRESSED" })
  return new Uint8Array(buffer)
}
