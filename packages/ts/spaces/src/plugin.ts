/**
 * Server companion for `starfish-spaces`.
 *
 * Exports two factory functions:
 *
 *   - `createSpacesRoleEnricher(store, layout?, options?)` — a `RoleEnricher`
 *     that grants `'space:owner'` / `'space:member'` from the space's `_access`
 *     registry doc. Defaults to `allowTofu: false` (absent doc → Forbidden).
 *     Pass `{ allowTofu: true }` only where first-create provisioning is needed.
 *
 *   - `createSpacesDirectoryServerPlugin(layout?)` — a `ServerPlugin` with an
 *     `afterWrite` hook that maintains the global public-object directory by
 *     projecting the `public` nodes from each space's object index.
 */
import { makeRegistryRoleEnricher } from "@drakkar.software/starfish-sharing"
import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import type { CollectionConfig } from "@drakkar.software/starfish-server"

import type { SpaceLayout } from "./config.js"
import { defaultSpaceLayout } from "./layout.js"

// ── RoleEnricher for spaces ────────────────────────────────────────────────────

/** Minimal store interface accepted by `makeRegistryRoleEnricher`. */
export interface SpaceObjectStore {
  getString(key: string): Promise<string | null>
}

/**
 * Creates a `RoleEnricher` that grants `'space:owner'` / `'space:member'` roles
 * from the space's `_access` registry doc.
 *
 * `allowTofu` controls what happens when the `_access` doc is absent:
 * - `false` (default): no roles → the caller is Forbidden. Use this on any read
 *   path (including cross-space batch reads) to prevent a caller from "claiming"
 *   an unclaimed spaceId by being the first to read it.
 * - `true`: grants owner + member (TOFU provisioning). Use only where you
 *   deliberately want first-writer-owns semantics (e.g. a space-creation flow).
 *
 * To combine multiple enrichers, use `composeEnrichers` from `starfish-server`.
 */
export function createSpacesRoleEnricher(
  store: SpaceObjectStore,
  layout: SpaceLayout = defaultSpaceLayout,
  options: { allowTofu?: boolean } = {},
): ReturnType<typeof makeRegistryRoleEnricher> {
  const { allowTofu = false } = options
  // The raw storage key for the _access doc (no /pull/ prefix — store keys are bare).
  // layout.spaceAccessPull('{id}') returns '/pull/spaces/{id}/_access';
  // strip the '/pull/' prefix.
  const registryPath = layout.spaceAccessPull("{id}").replace(/^\/pull\//, "")
  return makeRegistryRoleEnricher(store, {
    idParam: "spaceId",
    registryPath,
    ownerRole: "space:owner",
    memberRole: "space:member",
    allowTofu,
  })
}

/**
 * Returns the canonical server `CollectionConfig[]` for the space `_access`
 * registry collection.
 *
 * Register these on your server alongside
 * `createSpacesRoleEnricher(store)` so callers can batch-read `_access` across
 * many spaces in a single request using the account-scoped shared client
 * (`session.spacesRegistryClient`).
 *
 * Security notes:
 * - `readRoles: ["space:member"]` — only the space owner / declared members can
 *   read. The strict enricher (no TOFU) ensures missing spaces yield Forbidden.
 * - `writeRoles: ["space:owner"]` — only the space owner may modify the roster.
 * - Do NOT include `_keyring` or `_members` in this set; they are gated
 *   separately and must not be reachable via the cross-space batch route.
 */
export function spacesCollections(layout: SpaceLayout = defaultSpaceLayout): CollectionConfig[] {
  // storagePath is the bare key without /pull/ prefix.
  const storagePath = layout.spaceAccessPull("{spaceId}").replace(/^\/pull\//, "")
  return [
    {
      name: "spaceaccess",
      storagePath,
      readRoles: ["space:member"],
      writeRoles: ["space:owner"],
      encryption: "none",
      maxBodyBytes: 64 * 1024,
      allowedMimeTypes: ["application/json"],
    },
  ]
}

// ── Object directory server plugin ────────────────────────────────────────────

/**
 * Minimal store interface for the directory plugin: raw key-value writes.
 */
export interface DirectoryStore {
  getString(key: string): Promise<string | null>
  putString(key: string, value: string): Promise<void>
}

/**
 * Creates a `ServerPlugin` with an `afterWrite` hook that maintains the global
 * public-object directory.
 *
 * The hook fires when a write hits the `objindex` collection and the path matches
 * `spaces/{spaceId}/objects/_index`. It:
 *   1. Reads the written index doc's `objects` array from the event body.
 *   2. Filters for nodes where `access === 'public'`.
 *   3. Builds a directory entry bucket for this space.
 *   4. Reads the current public directory doc, merges/replaces this space's bucket.
 *   5. Writes the updated directory doc to the raw key `_index/objects/public`.
 *
 * Errors in the hook are logged and swallowed — a hook outage must not break
 * client writes.
 */
export function createSpacesDirectoryServerPlugin(
  store: DirectoryStore,
  layout: SpaceLayout = defaultSpaceLayout,
): ServerPlugin {
  // The storage key for the public directory doc (no leading slash, no /pull/).
  const dirKey = layout.objectDirPull("public").replace(/^\/pull\//, "")

  return {
    name: "starfish-spaces-directory",
    afterWrite: async (event: WriteEvent) => {
      try {
        if (event.collection !== "objindex") return

        // Check path matches spaces/{spaceId}/objects/_index
        const spaceId = event.params["spaceId"]
        if (!spaceId) return

        // Read the written objects array from the event body.
        const objects = (event.body?.objects ?? []) as Array<{
          id?: unknown
          type?: unknown
          title?: unknown
          emoji?: unknown
          updatedAt?: unknown
          access?: unknown
          enc?: unknown
        }>
        if (!Array.isArray(objects)) return

        // Filter for public nodes (access === 'public'; public+enc is invalid by protocol).
        const publicNodes = objects
          .filter((n) => n.access === "public" && !n.enc)
          .map((n) => ({
            id: n.id,
            type: n.type,
            title: n.title,
            ...(n.emoji !== undefined ? { emoji: n.emoji } : {}),
            updatedAt: n.updatedAt,
          }))

        // Read current directory doc (may be absent).
        let dirDoc: Record<string, { nodes: unknown[] }> = {}
        try {
          const raw = await store.getString(dirKey)
          if (raw) {
            const parsed = JSON.parse(raw) as unknown
            if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
              // The doc may be stored as `{ data: { ... } }` or bare.
              const candidate =
                "data" in (parsed as Record<string, unknown>)
                  ? (parsed as Record<string, unknown>).data
                  : parsed
              if (candidate && typeof candidate === "object") {
                dirDoc = candidate as Record<string, { nodes: unknown[] }>
              }
            }
          }
        } catch {
          // Corrupt or missing — start fresh.
          dirDoc = {}
        }

        // Update or remove this space's bucket.
        if (publicNodes.length > 0) {
          dirDoc = { ...dirDoc, [spaceId]: { nodes: publicNodes } }
        } else {
          const { [spaceId]: _removed, ...rest } = dirDoc
          dirDoc = rest
        }

        await store.putString(dirKey, JSON.stringify({ v: 1, ...dirDoc }))
      } catch (err) {
        console.error("[starfish-spaces] directory afterWrite hook failed:", err)
      }
    },
  }
}
