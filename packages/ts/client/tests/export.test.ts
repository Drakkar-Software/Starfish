import { describe, it, expect } from "vitest"
import { exportData, importData, exportToBlob } from "../src/export.js"

describe("exportData", () => {
  it("exports JSON by default", () => {
    const data = { theme: "dark", count: 42 }
    const result = exportData(data)
    expect(JSON.parse(result)).toEqual(data)
  })

  it("exports pretty JSON", () => {
    const data = { a: 1 }
    const result = exportData(data, { pretty: true })
    expect(result).toContain("\n")
    expect(JSON.parse(result)).toEqual(data)
  })

  it("exports CSV", () => {
    const data = { name: "Alice", age: 30 }
    const csv = exportData(data, { format: "csv" })
    const lines = csv.split("\n")
    expect(lines).toHaveLength(2)
    expect(lines[0]).toBe("name,age")
    expect(lines[1]).toBe("Alice,30")
  })

  it("exports CSV with complex values", () => {
    const data = { items: [1, 2, 3], name: "test" }
    const csv = exportData(data, { format: "csv" })
    expect(csv).toContain("items")
    expect(csv).toContain("name")
  })

  it("escapes CSV fields with commas", () => {
    const data = { value: "hello, world" }
    const csv = exportData(data, { format: "csv" })
    expect(csv).toContain('"hello, world"')
  })
})

describe("importData", () => {
  it("imports JSON", () => {
    const data = { theme: "dark", count: 42 }
    const result = importData(JSON.stringify(data))
    expect(result).toEqual(data)
  })

  it("throws for non-object JSON", () => {
    expect(() => importData('"string"')).toThrow("Expected a JSON object")
    expect(() => importData("[1,2,3]")).toThrow("Expected a JSON object")
  })

  it("imports CSV", () => {
    const csv = "name,age\nAlice,30"
    const result = importData(csv, "csv")
    expect(result["name"]).toBe("Alice")
    expect(result["age"]).toBe(30) // parsed as JSON number
  })

  it("imports CSV with JSON values", () => {
    const csv = 'items,name\n"[1,2,3]",test'
    const result = importData(csv, "csv")
    expect(result["items"]).toEqual([1, 2, 3])
    expect(result["name"]).toBe("test")
  })

  it("throws for CSV without data row", () => {
    expect(() => importData("header", "csv")).toThrow("at least a header row")
  })
})

describe("exportToBlob", () => {
  it("creates JSON blob", () => {
    const blob = exportToBlob({ a: 1 })
    expect(blob.type).toContain("application/json")
    expect(blob.size).toBeGreaterThan(0)
  })

  it("creates CSV blob", () => {
    const blob = exportToBlob({ a: 1 }, { format: "csv" })
    expect(blob.type).toContain("text/csv")
    expect(blob.size).toBeGreaterThan(0)
  })
})
