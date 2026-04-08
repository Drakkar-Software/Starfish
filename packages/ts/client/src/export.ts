/**
 * Data export/import helpers for Starfish sync data.
 * Supports JSON and CSV formats.
 */

export interface ExportOptions {
  /** Output format. Default: "json" */
  format?: "json" | "csv"
  /** Pretty-print JSON output. Default: false */
  pretty?: boolean
}

/**
 * Export data to a string representation.
 * JSON: serializes the full object.
 * CSV: flattens top-level keys into columns. Array values are JSON-encoded.
 */
export function exportData(
  data: Record<string, unknown>,
  opts?: ExportOptions,
): string {
  const format = opts?.format ?? "json"

  if (format === "json") {
    return opts?.pretty
      ? JSON.stringify(data, null, 2)
      : JSON.stringify(data)
  }

  // CSV export: each top-level key becomes a column
  return toCsv(data)
}

/**
 * Import data from a string representation.
 */
export function importData(
  raw: string,
  format: "json" | "csv" = "json",
): Record<string, unknown> {
  if (format === "json") {
    const parsed = JSON.parse(raw)
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("Expected a JSON object")
    }
    return parsed as Record<string, unknown>
  }

  return fromCsv(raw)
}

/**
 * Export data to a Blob suitable for download.
 */
export function exportToBlob(
  data: Record<string, unknown>,
  opts?: ExportOptions,
): Blob {
  const format = opts?.format ?? "json"
  const content = exportData(data, opts)
  const mimeType = format === "csv" ? "text/csv;charset=utf-8" : "application/json;charset=utf-8"
  return new Blob([content], { type: mimeType })
}

function toCsv(data: Record<string, unknown>): string {
  const keys = Object.keys(data)
  const header = keys.map(escapeCsvField).join(",")

  const values = keys.map((k) => {
    const v = data[k]
    if (v === null || v === undefined) return ""
    if (typeof v === "object") return escapeCsvField(JSON.stringify(v))
    return escapeCsvField(String(v))
  })

  return `${header}\n${values.join(",")}`
}

function fromCsv(raw: string): Record<string, unknown> {
  const lines = raw.trim().split("\n")
  if (lines.length < 2) {
    throw new Error("CSV must have at least a header row and a data row")
  }

  const headers = parseCsvLine(lines[0]!)
  const values = parseCsvLine(lines[1]!)

  const result: Record<string, unknown> = {}
  for (let i = 0; i < headers.length; i++) {
    const key = headers[i]!
    const val = values[i] ?? ""
    // Try to parse JSON values
    try {
      result[key] = JSON.parse(val)
    } catch {
      result[key] = val
    }
  }
  return result
}

function escapeCsvField(field: string): string {
  if (field.includes(",") || field.includes('"') || field.includes("\n")) {
    return `"${field.replace(/"/g, '""')}"`
  }
  return field
}

function parseCsvLine(line: string): string[] {
  const result: string[] = []
  let current = ""
  let inQuotes = false

  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') {
        current += '"'
        i++
      } else if (ch === '"') {
        inQuotes = false
      } else {
        current += ch
      }
    } else {
      if (ch === '"') {
        inQuotes = true
      } else if (ch === ",") {
        result.push(current)
        current = ""
      } else {
        current += ch
      }
    }
  }
  result.push(current)
  return result
}
