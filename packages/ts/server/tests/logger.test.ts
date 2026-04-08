import { describe, it, expect, vi } from "vitest"
import { createConsoleLogger, createJsonLogger, createNoopLogger } from "../src/logger.js"

describe("createConsoleLogger", () => {
  it("logs info level and above by default", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createConsoleLogger()
    logger.log({ level: "info", message: "test", timestamp: Date.now() })
    expect(spy).toHaveBeenCalledOnce()
    spy.mockRestore()
  })

  it("filters debug when minLevel is info", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createConsoleLogger("info")
    logger.log({ level: "debug", message: "debug msg", timestamp: Date.now() })
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })

  it("uses console.error for error level", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {})
    const logger = createConsoleLogger()
    logger.log({ level: "error", message: "err", timestamp: Date.now() })
    expect(spy).toHaveBeenCalledOnce()
    spy.mockRestore()
  })
})

describe("createJsonLogger", () => {
  it("outputs JSON lines", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createJsonLogger()
    logger.log({ level: "info", message: "test", timestamp: 1234 })
    expect(spy).toHaveBeenCalledWith(expect.stringContaining('"message":"test"'))
    spy.mockRestore()
  })
})

describe("createNoopLogger", () => {
  it("does not output anything", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createNoopLogger()
    logger.log({ level: "info", message: "test", timestamp: Date.now() })
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })
})
