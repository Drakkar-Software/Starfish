/**
 * Unit tests for encodeParquet cell coercion.
 *
 * Non-string cell values must serialize to the same canonical string the Python
 * encoder produces (`json.dumps(sort_keys=True, separators=(",",":"),
 * ensure_ascii=False)`), so DuckDB reads identical data regardless of backend.
 */
import { describe, it, expect } from "vitest"
import { encodeParquet } from "../src/encode.js"
import { parquetReadObjects } from "hyparquet"

/** Wrap an ArrayBuffer as an AsyncBuffer for hyparquet. */
function toAsyncBuffer(buf: ArrayBuffer) {
  return {
    byteLength: buf.byteLength,
    slice: (start: number, end?: number) => buf.slice(start, end),
  }
}

async function decodeRows(bytes: Uint8Array) {
  return parquetReadObjects({ file: toAsyncBuffer(bytes.buffer as ArrayBuffer) })
}

describe("encodeParquet cell coercion", () => {
  it("serializes non-string values as canonical key-sorted JSON matching Python", async () => {
    const rows = [
      {
        event_type: true, // boolean → "true"
        message_id: 42, // number → "42"
        properties: { z: 1, a: { d: 4, c: 3 } }, // nested object, keys sorted recursively
        context: ["b", "a"], // array order preserved, not sorted
      },
    ]
    const decoded = await decodeRows(encodeParquet(rows))
    expect(decoded[0]?.["event_type"]).toBe("true")
    expect(decoded[0]?.["message_id"]).toBe("42")
    expect(decoded[0]?.["properties"]).toBe('{"a":{"c":3,"d":4},"z":1}')
    expect(decoded[0]?.["context"]).toBe('["b","a"]')
  })

  it("passes strings through verbatim and maps null/undefined to empty string", async () => {
    const rows = [{ properties: '{"already":"json"}', distinct_id: null }]
    const decoded = await decodeRows(encodeParquet(rows))
    expect(decoded[0]?.["properties"]).toBe('{"already":"json"}')
    expect(decoded[0]?.["distinct_id"]).toBe("")
  })
})
