import { describe, it, expect } from "vitest"
import type { AuthorizeContext, SyncConfig } from "@drakkar.software/starfish-server"
import {
  createRestrictionsPlugin,
  restrictionsFromConfig,
  type RestrictionRule,
} from "../src/index.js"

function ctx(over: Partial<AuthorizeContext> = {}): AuthorizeContext {
  return {
    identity: "alice",
    action: "pull",
    collection: "notes",
    params: {},
    roles: [],
    ...over,
  }
}

async function decide(rules: RestrictionRule[], c: AuthorizeContext) {
  const plugin = createRestrictionsPlugin({ rules })
  return plugin.authorize!(c)
}

describe("createRestrictionsPlugin — deny mode", () => {
  it("denies a listed identity server-wide", async () => {
    const r = await decide([{ mode: "deny", identities: ["alice"] }], ctx())
    expect(r.action).toBe("reject")
    expect(r).toMatchObject({ status: 403, error: "identity restricted" })
  })

  it("allows an unlisted identity", async () => {
    const r = await decide([{ mode: "deny", identities: ["bob"] }], ctx({ identity: "alice" }))
    expect(r.action).toBe("proceed")
  })

  it("never denies an anonymous caller under a deny rule", async () => {
    const r = await decide([{ mode: "deny", identities: ["alice"] }], ctx({ identity: undefined }))
    expect(r.action).toBe("proceed")
  })
})

describe("createRestrictionsPlugin — allow mode", () => {
  it("permits only listed identities", async () => {
    const rules: RestrictionRule[] = [{ mode: "allow", identities: ["alice"] }]
    expect((await decide(rules, ctx({ identity: "alice" }))).action).toBe("proceed")
    expect((await decide(rules, ctx({ identity: "carol" }))).action).toBe("reject")
  })

  it("blocks anonymous callers under an allow rule", async () => {
    const r = await decide([{ mode: "allow", identities: ["alice"] }], ctx({ identity: undefined }))
    expect(r.action).toBe("reject")
  })

  it("requires the caller to satisfy EVERY applicable allow rule", async () => {
    const rules: RestrictionRule[] = [
      { mode: "allow", identities: ["alice", "bob"] },
      { mode: "allow", identities: ["alice"], scope: { collection: "notes" } },
    ]
    expect((await decide(rules, ctx({ identity: "alice" }))).action).toBe("proceed")
    // bob passes the server-wide allow but not the notes-only allow
    expect((await decide(rules, ctx({ identity: "bob" }))).action).toBe("reject")
  })
})

describe("createRestrictionsPlugin — deny beats allow", () => {
  it("rejects even when an allow rule would permit", async () => {
    const rules: RestrictionRule[] = [
      { mode: "allow", identities: ["alice"] },
      { mode: "deny", identities: ["alice"], scope: { action: "pull" } },
    ]
    expect((await decide(rules, ctx({ identity: "alice", action: "pull" }))).action).toBe("reject")
  })
})

describe("createRestrictionsPlugin — scoping", () => {
  it("matches by action", async () => {
    const rules: RestrictionRule[] = [
      { mode: "deny", identities: ["alice"], scope: { action: "push" } },
    ]
    expect((await decide(rules, ctx({ action: "push" }))).action).toBe("reject")
    expect((await decide(rules, ctx({ action: "pull" }))).action).toBe("proceed")
  })

  it("matches by collection", async () => {
    const rules: RestrictionRule[] = [
      { mode: "deny", identities: ["alice"], scope: { collection: "secret" } },
    ]
    expect((await decide(rules, ctx({ collection: "secret" }))).action).toBe("reject")
    expect((await decide(rules, ctx({ collection: "notes" }))).action).toBe("proceed")
  })

  it("matches by namespace, and null targets the root", async () => {
    const nsRule: RestrictionRule[] = [
      { mode: "deny", identities: ["alice"], scope: { namespace: "acme" } },
    ]
    expect((await decide(nsRule, ctx({ namespace: "acme" }))).action).toBe("reject")
    expect((await decide(nsRule, ctx({ namespace: undefined }))).action).toBe("proceed")

    const rootRule: RestrictionRule[] = [
      { mode: "deny", identities: ["alice"], scope: { namespace: null } },
    ]
    expect((await decide(rootRule, ctx({ namespace: undefined }))).action).toBe("reject")
    expect((await decide(rootRule, ctx({ namespace: "acme" }))).action).toBe("proceed")
  })
})

describe("createRestrictionsPlugin — callback identities", () => {
  it("resolves a sync callback with the request context", async () => {
    const rules: RestrictionRule[] = [
      { mode: "deny", identities: (c) => (c.collection === "notes" ? ["alice"] : []) },
    ]
    expect((await decide(rules, ctx({ collection: "notes" }))).action).toBe("reject")
    expect((await decide(rules, ctx({ collection: "other" }))).action).toBe("proceed")
  })

  it("resolves an async callback", async () => {
    const rules: RestrictionRule[] = [
      { mode: "deny", identities: async () => ["alice"] },
    ]
    expect((await decide(rules, ctx())).action).toBe("reject")
  })
})

describe("restrictionsFromConfig", () => {
  const config: SyncConfig = {
    version: 1,
    restrictions: [{ mode: "deny", identities: ["server-bad"] }],
    collections: [
      {
        name: "notes",
        storagePath: "notes/{identity}",
        readRoles: ["self"],
        writeRoles: ["self"],
        encryption: "none",
        maxBodyBytes: 1024,
        allowedMimeTypes: ["application/json"],
        restrictions: [{ mode: "deny", identities: ["notes-bad"], actions: ["push"] }],
      },
    ],
    namespaces: {
      acme: {
        restrictions: [{ mode: "allow", identities: ["acme-user"] }],
        collections: [
          {
            name: "settings",
            storagePath: "settings/{identity}",
            readRoles: ["self"],
            writeRoles: ["self"],
            encryption: "none",
            maxBodyBytes: 1024,
            allowedMimeTypes: ["application/json"],
          },
        ],
      },
    },
  }

  it("compiles server, collection (with actions), and namespace rules", () => {
    const rules = restrictionsFromConfig(config)
    // server-wide deny (no scope)
    expect(rules).toContainEqual({ mode: "deny", identities: ["server-bad"] })
    // collection push-only deny, scoped to root namespace + collection
    expect(rules).toContainEqual({
      mode: "deny",
      identities: ["notes-bad"],
      scope: { namespace: null, collection: "notes", action: "push" },
    })
    // namespace-level allow
    expect(rules).toContainEqual({
      mode: "allow",
      identities: ["acme-user"],
      scope: { namespace: "acme" },
    })
  })

  it("enforces compiled config rules through the plugin", async () => {
    const plugin = createRestrictionsPlugin({ config })
    const denied = await plugin.authorize!(ctx({ identity: "server-bad", collection: "notes" }))
    expect(denied.action).toBe("reject")
    const pushBlocked = await plugin.authorize!(
      ctx({ identity: "notes-bad", collection: "notes", action: "push" }),
    )
    expect(pushBlocked.action).toBe("reject")
    const pullOk = await plugin.authorize!(
      ctx({ identity: "notes-bad", collection: "notes", action: "pull" }),
    )
    expect(pullOk.action).toBe("proceed")
  })

  it("isolates a root collection rule from a same-named namespaced collection", () => {
    // A root-level `notes` deny and a namespaced `notes` collection with the
    // same name must not bleed into each other.
    const cfg: SyncConfig = {
      version: 1,
      collections: [
        {
          name: "notes",
          storagePath: "notes/{identity}",
          readRoles: ["self"],
          writeRoles: ["self"],
          encryption: "none",
          maxBodyBytes: 1024,
          allowedMimeTypes: ["application/json"],
          restrictions: [{ mode: "deny", identities: ["alice"] }],
        },
      ],
      namespaces: {
        acme: {
          collections: [
            {
              name: "notes",
              storagePath: "notes/{identity}",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1024,
              allowedMimeTypes: ["application/json"],
            },
          ],
        },
      },
    }
    const plugin = createRestrictionsPlugin({ config: cfg })
    return Promise.all([
      // root notes → denied
      plugin.authorize!(ctx({ identity: "alice", collection: "notes", namespace: undefined })),
      // acme/notes (same name, different scope) → not denied
      plugin.authorize!(ctx({ identity: "alice", collection: "notes", namespace: "acme" })),
    ]).then(([rootRes, nsRes]) => {
      expect(rootRes.action).toBe("reject")
      expect(nsRes.action).toBe("proceed")
    })
  })

  it("compiles and enforces a namespace-collection-level restriction", async () => {
    const cfg: SyncConfig = {
      version: 1,
      collections: [],
      namespaces: {
        acme: {
          collections: [
            {
              name: "settings",
              storagePath: "settings/{identity}",
              readRoles: ["self"],
              writeRoles: ["self"],
              encryption: "none",
              maxBodyBytes: 1024,
              allowedMimeTypes: ["application/json"],
              restrictions: [{ mode: "deny", identities: ["ns-col-bad"] }],
            },
          ],
        },
      },
    }
    const rules = restrictionsFromConfig(cfg)
    expect(rules).toContainEqual({
      mode: "deny",
      identities: ["ns-col-bad"],
      scope: { namespace: "acme", collection: "settings" },
    })
    const plugin = createRestrictionsPlugin({ config: cfg })
    expect(
      (await plugin.authorize!(ctx({ identity: "ns-col-bad", collection: "settings", namespace: "acme" }))).action,
    ).toBe("reject")
    // same collection name at root is unaffected
    expect(
      (await plugin.authorize!(ctx({ identity: "ns-col-bad", collection: "settings", namespace: undefined }))).action,
    ).toBe("proceed")
  })
})
