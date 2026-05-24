import { describe, it, expect } from "vitest"
import { validateReplicaConfig } from "../src/validate.js"
import type { RemoteConfig } from "../src/config.js"
import type { SyncConfig, CollectionConfig } from "@drakkar.software/starfish-server"

function col(overrides: Partial<CollectionConfig> = {}): CollectionConfig {
  return {
    name: "posts",
    storagePath: "posts/featured",
    readRoles: ["public"],
    writeRoles: ["self"],
    encryption: "none",
    maxBodyBytes: 1_000_000,
    allowedMimeTypes: ["application/json"],
    ...overrides,
  }
}

function config(...cols: CollectionConfig[]): SyncConfig {
  return { version: 1, collections: cols }
}

function remote(overrides: Partial<RemoteConfig> = {}): RemoteConfig {
  return {
    url: "https://primary.example.com",
    pullPath: "/pull/posts/featured",
    intervalMs: 60_000,
    headers: {},
    writeMode: "pull_only",
    syncTriggers: ["scheduled"],
    ...overrides,
  }
}

describe("validateReplicaConfig", () => {
  it("accepts a valid pull_only remote collection", () => {
    expect(validateReplicaConfig(config(col()), { posts: remote() })).toEqual([])
  })

  it("rejects remote configured for an unknown collection", () => {
    const errors = validateReplicaConfig(config(col()), { ghost: remote() })
    expect(errors.some((e) => e.includes("unknown root collection"))).toBe(true)
  })

  it("rejects appendOnly + remote", () => {
    const errors = validateReplicaConfig(config(col({ appendOnly: { type: "by_timestamp" } })), { posts: remote() })
    expect(errors.some((e) => e.includes("appendOnly cannot be used with remote replication"))).toBe(true)
  })

  it("rejects binary + remote", () => {
    const errors = validateReplicaConfig(
      config(col({ allowedMimeTypes: ["image/png"] })),
      { posts: remote() },
    )
    expect(errors.some((e) => e.includes("binary collections cannot have remote replication"))).toBe(true)
  })

  it("rejects template variables in storagePath", () => {
    const errors = validateReplicaConfig(
      config(col({ storagePath: "posts/{id}" })),
      { posts: remote() },
    )
    expect(errors.some((e) => e.includes("static storagePath"))).toBe(true)
  })

  it("rejects pushOnly + remote", () => {
    const errors = validateReplicaConfig(config(col({ pushOnly: true })), { posts: remote() })
    expect(errors.some((e) => e.includes("cannot be pushOnly"))).toBe(true)
  })

  it("rejects bundle + remote", () => {
    const errors = validateReplicaConfig(config(col({ bundle: "b1" })), { posts: remote() })
    expect(errors.some((e) => e.includes("cannot be part of a bundle"))).toBe(true)
  })

  it("rejects delegated encryption + remote", () => {
    const errors = validateReplicaConfig(config(col({ encryption: "delegated" })), { posts: remote() })
    expect(errors.some((e) => e.includes("cannot use \"delegated\" encryption"))).toBe(true)
  })

  it("requires pushPath for push_through / bidirectional", () => {
    const pt = validateReplicaConfig(config(col()), { posts: remote({ writeMode: "push_through" }) })
    expect(pt.some((e) => e.includes("requires remote.pushPath"))).toBe(true)
    const bi = validateReplicaConfig(config(col()), { posts: remote({ writeMode: "bidirectional" }) })
    expect(bi.some((e) => e.includes("requires remote.pushPath"))).toBe(true)
    const ok = validateReplicaConfig(
      config(col()),
      { posts: remote({ writeMode: "push_through", pushPath: "/push/posts/featured" }) },
    )
    expect(ok).toEqual([])
  })
})
