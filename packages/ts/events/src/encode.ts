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
    data: rows.map((r) => coerceCell(r[name])),
  }))

  const buffer = parquetWriteBuffer({ columnData, codec: "UNCOMPRESSED" })
  return new Uint8Array(buffer)
}

/**
 * Coerce one cell value to the canonical string stored in Parquet.
 *
 * `null`/`undefined` → `""`; strings pass through verbatim; every other JSON
 * value (object, array, number, boolean) is serialized as compact JSON with
 * recursively-sorted object keys. This must stay identical to the Python encoder
 * (`json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`)
 * so DuckDB sees the same strings regardless of which backend produced the file.
 */
function coerceCell(value: unknown): string {
  if (value == null) return ""
  if (typeof value === "string") return value
  return JSON.stringify(sortDeep(value))
}

/** Recursively sort object keys so `JSON.stringify` output matches Python's `sort_keys=True`. */
function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep)
  if (value && typeof value === "object") {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortDeep((value as Record<string, unknown>)[key])
    }
    return sorted
  }
  return value
}
