import type { SyncConfig, CollectionConfig } from "@drakkar.software/starfish-server"
import { ENCRYPTION_DELEGATED } from "@drakkar.software/starfish-server"
import type { RemoteConfig } from "./config.js"

const MIME_JSON = "application/json"

function isBinaryCollection(allowedMimeTypes: string[]): boolean {
  return !allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}

/**
 * Validate the replica configuration by cross-referencing the `remotes` map
 * (collection name → `RemoteConfig`) against the server's `SyncConfig`
 * collections. Returns error messages (empty = valid).
 *
 * The core server schema no longer carries a `remote` field, so these
 * cross-cutting rules — which were previously inline in
 * `starfish-server`'s config validator — now live with the plugin that owns
 * the replica config.
 */
export function validateReplicaConfig(
  config: SyncConfig,
  remotes: Record<string, RemoteConfig>,
): string[] {
  const errors: string[] = []
  const byName = new Map<string, CollectionConfig>(
    config.collections.map((c) => [c.name, c]),
  )

  for (const [name, remote] of Object.entries(remotes)) {
    const col = byName.get(name)
    if (!col) {
      errors.push(
        `Collection "${name}": remote replication configured for an unknown root collection`,
      )
      continue
    }

    if (col.appendOnly) {
      errors.push(`Collection "${name}": appendOnly cannot be used with remote replication`)
    }
    if (isBinaryCollection(col.allowedMimeTypes)) {
      errors.push(`Collection "${name}": binary collections cannot have remote replication`)
    }
    if (/\{[^}]+\}/.test(col.storagePath)) {
      errors.push(
        `Collection "${name}": remote collections must have a static storagePath with no template variables (found "${col.storagePath}")`,
      )
    }
    if (col.pushOnly) {
      errors.push(`Collection "${name}": remote collections cannot be pushOnly`)
    }
    if (col.bundle) {
      errors.push(`Collection "${name}": remote collections cannot be part of a bundle`)
    }
    if (col.encryption === ENCRYPTION_DELEGATED) {
      errors.push(
        `Collection "${name}": remote collections cannot use "${col.encryption}" encryption (server cannot replicate opaque client-encrypted blobs)`,
      )
    }
    if (
      (remote.writeMode === "push_through" || remote.writeMode === "bidirectional") &&
      !remote.pushPath
    ) {
      errors.push(
        `Collection "${name}": write_mode "${remote.writeMode}" requires remote.pushPath to be set`,
      )
    }
  }

  return errors
}
