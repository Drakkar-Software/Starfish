/**
 * Server companion for `starfish-spaces`.
 *
 * Exports two factory functions:
 *
 *   - `createSpacesRoleEnricher(store, layout?)` — a `RoleEnricher` that grants
 *     `'space:owner'` / `'space:member'` from the space's `_access` registry doc.
 *
 *   - `createSpacesDirectoryServerPlugin(layout?)` — a `ServerPlugin` with an
 *     `afterWrite` hook that maintains the global public-object directory by
 *     projecting the `public` nodes from each space's object index.
 */
import { makeRegistryRoleEnricher } from "@drakkar.software/starfish-sharing"
import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"

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
 * Pass the SpaceLayout so the enricher reads from the correct path.
 * The `registryPath` is the raw storage key WITHOUT the `/pull/` prefix.
 */
export function createSpacesRoleEnricher(
  store: SpaceObjectStore,
  layout: SpaceLayout = defaultSpaceLayout,
): ReturnType<typeof makeRegistryRoleEnricher> {
  // The raw storage key for the _access doc (no /pull/ prefix — store keys are bare).
  // layout.spaceAccessPull('{id}') returns '/pull/spaces/{id}/_access';
  // strip the '/pull/' prefix.
  const registryPath = layout.spaceAccessPull("{id}").replace(/^\/pull\//, "")
  return makeRegistryRoleEnricher(store, {
    idParam: "spaceId",
    registryPath,
    ownerRole: "space:owner",
    memberRole: "space:member",
    allowTofu: true,
  })
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
