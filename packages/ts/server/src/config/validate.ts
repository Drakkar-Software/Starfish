import type { SyncConfig } from "./schema.js"
import {
  ENCRYPTION_IDENTITY,
  ENCRYPTION_SERVER,
  ENCRYPTION_DELEGATED,
  IDENTITY_PARAM,
  ROLE_PUBLIC,
} from "../constants.js"

const MIME_JSON = "application/json"

function isBinaryCollection(allowedMimeTypes: string[]): boolean {
  return !allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}

export function validateConfig(config: SyncConfig): string[] {
  const errors: string[] = []
  const names = new Set<string>()

  for (const col of config.collections) {
    if (names.has(col.name)) {
      errors.push(`Duplicate collection name: "${col.name}"`)
    }
    names.add(col.name)

    if (col.storagePath.startsWith("/")) {
      errors.push(`Collection "${col.name}": storagePath must not start with /`)
    }

    if (col.pullOnly && col.pushOnly) {
      errors.push(`Collection "${col.name}": cannot be both pullOnly and pushOnly`)
    }

    if (col.readRoles.includes(ROLE_PUBLIC) && col.encryption === ENCRYPTION_IDENTITY) {
      errors.push(
        `Collection "${col.name}": public collections must not use "${ENCRYPTION_IDENTITY}" encryption (key would be derived from empty identity)`,
      )
    }

    if (col.bundle && col.encryption !== ENCRYPTION_IDENTITY) {
      errors.push(
        `Collection "${col.name}": bundled collections must use "${ENCRYPTION_IDENTITY}" encryption`,
      )
    }

    if (col.bundle && !col.storagePath.includes(IDENTITY_PARAM)) {
      errors.push(
        `Collection "${col.name}": bundled collections must have ${IDENTITY_PARAM} in storagePath`,
      )
    }

    if (!col.pullOnly && col.readRoles.length === 0) {
      errors.push(
        `Collection "${col.name}": readRoles must not be empty (use ["${ROLE_PUBLIC}"] for public access)`,
      )
    }

    const isBinary = isBinaryCollection(col.allowedMimeTypes)
    if (isBinary) {
      if (col.encryption === ENCRYPTION_IDENTITY || col.encryption === ENCRYPTION_SERVER) {
        errors.push(
          `Collection "${col.name}": binary collections cannot use "${col.encryption}" encryption (storage layer is string-based)`,
        )
      }
      if (col.objectSchema != null) {
        errors.push(`Collection "${col.name}": binary collections cannot have objectSchema`)
      }
      if (col.bundle) {
        errors.push(`Collection "${col.name}": binary collections cannot be part of a bundle`)
      }
      if (col.remote) {
        errors.push(`Collection "${col.name}": binary collections cannot have remote replication`)
      }
    }
    if (col.allowedMimeTypes.length === 0) {
      errors.push(`Collection "${col.name}": allowedMimeTypes must contain at least one pattern`)
    }

    if (col.remote) {
      if (/\{[^}]+\}/.test(col.storagePath)) {
        errors.push(
          `Collection "${col.name}": remote collections must have a static storagePath with no template variables (found "${col.storagePath}")`,
        )
      }
      if (col.pushOnly) {
        errors.push(`Collection "${col.name}": remote collections cannot be pushOnly`)
      }
      if (col.bundle) {
        errors.push(`Collection "${col.name}": remote collections cannot be part of a bundle`)
      }
      if (col.encryption === ENCRYPTION_DELEGATED) {
        errors.push(
          `Collection "${col.name}": remote collections cannot use delegated encryption (server cannot replicate opaque client-encrypted blobs)`,
        )
      }
      if (
        (col.remote.writeMode === "push_through" || col.remote.writeMode === "bidirectional") &&
        !col.remote.pushPath
      ) {
        errors.push(
          `Collection "${col.name}": write_mode "${col.remote.writeMode}" requires remote.push_path to be set`,
        )
      }
    }
  }

  // Check bundles: all collections in same bundle must share storagePath
  const bundles = new Map<string, string>()
  for (const col of config.collections) {
    if (!col.bundle) continue
    const existing = bundles.get(col.bundle)
    if (existing && existing !== col.storagePath) {
      errors.push(
        `Bundle "${col.bundle}": all collections must share the same storagePath (found "${existing}" and "${col.storagePath}")`,
      )
    }
    bundles.set(col.bundle, col.storagePath)
  }

  return errors
}
