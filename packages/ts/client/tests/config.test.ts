import { describe, it, expect, vi } from "vitest"
import { fetchServerConfig } from "../src/config.js"
import type { ConfigResponse } from "../src/config.js"

const mockResponse: ConfigResponse = {
  collections: [
    {
      name: "posts",
      maxBodyBytes: 65536,
      encryption: "none",
      allowedMimeTypes: ["application/json"],
      publicKey: "base64key==",
    },
    {
      name: "events",
      maxBodyBytes: 16384,
      encryption: "none",
      allowedMimeTypes: ["application/json"],
      queueOnly: true,
    },
  ],
}

describe("fetchServerConfig", () => {
  it("fetches and returns typed ConfigResponse", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockResponse),
    })
    vi.stubGlobal("fetch", mockFetch)

    const result = await fetchServerConfig("https://api.example.com/v1")

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.example.com/v1/config",
      { method: "GET", headers: undefined },
    )
    expect(result.collections).toHaveLength(2)
    expect(result.collections[0].name).toBe("posts")
    expect(result.collections[0].publicKey).toBe("base64key==")
    expect(result.collections[1].queueOnly).toBe(true)

    vi.unstubAllGlobals()
  })

  it("strips trailing slash from baseUrl", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ collections: [] }),
    })
    vi.stubGlobal("fetch", mockFetch)

    await fetchServerConfig("https://api.example.com/v1/")

    expect(mockFetch).toHaveBeenCalledWith(
      "https://api.example.com/v1/config",
      expect.anything(),
    )

    vi.unstubAllGlobals()
  })

  it("passes custom headers", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ collections: [] }),
    })
    vi.stubGlobal("fetch", mockFetch)

    await fetchServerConfig("https://api.example.com/v1", {
      headers: { Authorization: "Bearer token" },
    })

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      { method: "GET", headers: { Authorization: "Bearer token" } },
    )

    vi.unstubAllGlobals()
  })

  it("throws on non-2xx response", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: "Not Found",
    })
    vi.stubGlobal("fetch", mockFetch)

    await expect(fetchServerConfig("https://api.example.com/v1")).rejects.toThrow("404")

    vi.unstubAllGlobals()
  })

  it("includes namespaces when present", async () => {
    const withNs: ConfigResponse = {
      collections: [],
      namespaces: {
        tenantA: {
          collections: [{ name: "settings", maxBodyBytes: 1024, encryption: "none", allowedMimeTypes: ["application/json"] }],
        },
      },
    }
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(withNs),
    })
    vi.stubGlobal("fetch", mockFetch)

    const result = await fetchServerConfig("https://api.example.com/v1")
    expect(result.namespaces?.tenantA?.collections[0].name).toBe("settings")

    vi.unstubAllGlobals()
  })
})
