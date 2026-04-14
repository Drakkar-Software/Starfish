import { describe, it, expect, vi } from "vitest"
import { pullEntitlements } from "../src/entitlements.js"
import { StarfishHttpError } from "../src/types.js"
import type { StarfishClient } from "../src/client.js"

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeMockClient(pullResult: unknown): StarfishClient {
  return {
    pull: vi.fn().mockResolvedValue(pullResult),
  } as unknown as StarfishClient
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("pullEntitlements", () => {
  it("returns the features list from the document", async () => {
    const client = makeMockClient({
      data: { features: ["premium-package-1", "paid-cloud-sync"] },
      hash: "abc",
      timestamp: 1000,
    })

    const features = await pullEntitlements(client, "alice")
    expect(features.sort()).toEqual(["paid-cloud-sync", "premium-package-1"])
  })

  it("returns empty array when features field is absent", async () => {
    const client = makeMockClient({ data: {}, hash: "abc", timestamp: 1000 })

    const features = await pullEntitlements(client, "alice")
    expect(features).toEqual([])
  })

  it("returns empty array when features field is not an array", async () => {
    const client = makeMockClient({ data: { features: "not-a-list" }, hash: "abc", timestamp: 1000 })

    const features = await pullEntitlements(client, "alice")
    expect(features).toEqual([])
  })

  it("returns empty array when data is null", async () => {
    const client = makeMockClient({ data: null, hash: null, timestamp: 0 })

    const features = await pullEntitlements(client, "alice")
    expect(features).toEqual([])
  })

  it("filters non-string elements from the features list", async () => {
    const client = makeMockClient({
      data: { features: ["valid", 42, null, true, "also-valid"] },
      hash: "abc",
      timestamp: 1000,
    })

    const features = await pullEntitlements(client, "alice")
    expect(features.sort()).toEqual(["also-valid", "valid"])
  })

  it("calls pull with the correct default path for the given userId", async () => {
    const pullSpy = vi.fn().mockResolvedValue({ data: { features: [] }, hash: null, timestamp: 0 })
    const client = { pull: pullSpy } as unknown as StarfishClient

    await pullEntitlements(client, "abc123")

    expect(pullSpy).toHaveBeenCalledWith("/pull/users/abc123/entitlements")
  })

  it("respects a custom path template", async () => {
    const pullSpy = vi.fn().mockResolvedValue({ data: { features: ["pro"] }, hash: null, timestamp: 0 })
    const client = { pull: pullSpy } as unknown as StarfishClient

    const features = await pullEntitlements(client, "alice", { path: "/pull/ents/{userId}" })

    expect(pullSpy).toHaveBeenCalledWith("/pull/ents/alice")
    expect(features).toEqual(["pro"])
  })

  it("respects a custom field option", async () => {
    const client = makeMockClient({ data: { slugs: ["pro"] }, hash: null, timestamp: 0 })

    const features = await pullEntitlements(client, "alice", { field: "slugs" })
    expect(features).toEqual(["pro"])
  })

  it("returns empty array when pull throws a 404", async () => {
    const client = {
      pull: vi.fn().mockRejectedValue(new StarfishHttpError(404, "Not Found")),
    } as unknown as StarfishClient

    const features = await pullEntitlements(client, "alice")
    expect(features).toEqual([])
  })

  it("re-throws non-404 HTTP errors", async () => {
    const client = {
      pull: vi.fn().mockRejectedValue(new StarfishHttpError(500, "Internal Server Error")),
    } as unknown as StarfishClient

    await expect(pullEntitlements(client, "alice")).rejects.toThrow(StarfishHttpError)
  })

  it("re-throws non-HTTP errors", async () => {
    const client = {
      pull: vi.fn().mockRejectedValue(new Error("network failure")),
    } as unknown as StarfishClient

    await expect(pullEntitlements(client, "alice")).rejects.toThrow("network failure")
  })
})
