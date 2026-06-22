/**
 * Tests for the CAS retry helper.
 */
import { describe, it, expect, vi } from "vitest"
import { ConflictError } from "@drakkar.software/starfish-client"
import { runCas } from "../src/cas-retry.js"

describe("runCas", () => {
  it("returns the result of the first successful call", async () => {
    const fn = vi.fn().mockResolvedValue("ok")
    expect(await runCas(fn)).toBe("ok")
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it("retries on ConflictError up to 3 times", async () => {
    const conflict = new ConflictError("conflict", 409)
    const fn = vi.fn()
      .mockRejectedValueOnce(conflict)
      .mockRejectedValueOnce(conflict)
      .mockResolvedValue("success")
    expect(await runCas(fn)).toBe("success")
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it("throws after 3 ConflictErrors (does not retry a 4th time)", async () => {
    const conflict = new ConflictError("conflict", 409)
    const fn = vi.fn().mockRejectedValue(conflict)
    await expect(runCas(fn)).rejects.toThrow(ConflictError)
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it("propagates non-conflict errors immediately", async () => {
    const boom = new Error("network error")
    const fn = vi.fn().mockRejectedValue(boom)
    await expect(runCas(fn)).rejects.toThrow("network error")
    expect(fn).toHaveBeenCalledTimes(1)
  })
})
