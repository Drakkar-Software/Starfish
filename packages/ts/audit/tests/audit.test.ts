import { describe, it, expect, vi } from "vitest"
import { createConsoleAuditLogger, createCallbackAuditLogger, createNoopAuditLogger, type AuditEntry } from "../src/audit.js"

const baseEntry: AuditEntry = {
  timestamp: Date.now(),
  action: "pull",
  collection: "settings",
  identity: "user-1",
  documentKey: "users/user-1/settings",
  success: true,
  statusCode: 200,
}

describe("createConsoleAuditLogger", () => {
  it("logs audit entries to console", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createConsoleAuditLogger()
    logger.record(baseEntry)
    expect(spy).toHaveBeenCalledOnce()
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("PULL"))
    spy.mockRestore()
  })
})

describe("createCallbackAuditLogger", () => {
  it("calls the callback with the entry", () => {
    const cb = vi.fn()
    const logger = createCallbackAuditLogger(cb)
    logger.record(baseEntry)
    expect(cb).toHaveBeenCalledWith(baseEntry)
  })
})

describe("createNoopAuditLogger", () => {
  it("does not call anything", () => {
    const spy = vi.spyOn(console, "log").mockImplementation(() => {})
    const logger = createNoopAuditLogger()
    logger.record(baseEntry)
    expect(spy).not.toHaveBeenCalled()
    spy.mockRestore()
  })
})
