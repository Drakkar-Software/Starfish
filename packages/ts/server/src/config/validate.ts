import type { SyncConfig, CollectionConfig } from "./schema.js"
import {
  ENCRYPTION_IDENTITY,
  ENCRYPTION_SERVER,
  ENCRYPTION_DELEGATED,
  IDENTITY_PARAM,
  ROLE_PUBLIC,
} from "../constants.js"

const MIME_JSON = "application/json"

const NAMESPACE_NAME_RE = /^[a-zA-Z0-9_-]+$/
const RESERVED_NAMESPACE_NAMES = new Set(["pull", "push", "health", "batch"])

function isBinaryCollection(allowedMimeTypes: string[]): boolean {
  return !allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}

function validateCollections(collections: CollectionConfig[], scopeLabel: string): string[] {
  const errors: string[] = []
  const names = new Set<string>()

  for (const col of collections) {
    if (names.has(col.name)) {
      errors.push(`${scopeLabel}Duplicate collection name: "${col.name}"`)
    }
    names.add(col.name)

    if (col.storagePath.startsWith("/")) {
      errors.push(`${scopeLabel}Collection "${col.name}": storagePath must not start with /`)
    }

    if (col.pullOnly && col.pushOnly) {
      errors.push(`${scopeLabel}Collection "${col.name}": cannot be both pullOnly and pushOnly`)
    }

    if (col.readRoles.includes(ROLE_PUBLIC) && col.encryption === ENCRYPTION_IDENTITY) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": public collections must not use "${ENCRYPTION_IDENTITY}" encryption (key would be derived from empty identity)`,
      )
    }

    if (col.bundle && col.encryption !== ENCRYPTION_IDENTITY) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": bundled collections must use "${ENCRYPTION_IDENTITY}" encryption`,
      )
    }

    if (col.bundle && !col.storagePath.includes(IDENTITY_PARAM)) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": bundled collections must have ${IDENTITY_PARAM} in storagePath`,
      )
    }

    if (!col.pullOnly && col.readRoles.length === 0) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": readRoles must not be empty (use ["${ROLE_PUBLIC}"] for public access)`,
      )
    }

    const isBinary = isBinaryCollection(col.allowedMimeTypes)
    if (isBinary) {
      if (col.encryption === ENCRYPTION_IDENTITY || col.encryption === ENCRYPTION_SERVER) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": binary collections cannot use "${col.encryption}" encryption (storage layer is string-based)`,
        )
      }
      if (col.objectSchema != null) {
        errors.push(`${scopeLabel}Collection "${col.name}": binary collections cannot have objectSchema`)
      }
      if (col.bundle) {
        errors.push(`${scopeLabel}Collection "${col.name}": binary collections cannot be part of a bundle`)
      }
      if (col.remote) {
        errors.push(`${scopeLabel}Collection "${col.name}": binary collections cannot have remote replication`)
      }
    }
    if (col.allowedMimeTypes.length === 0) {
      errors.push(`${scopeLabel}Collection "${col.name}": allowedMimeTypes must contain at least one pattern`)
    }

    if (col.remote) {
      if (/\{[^}]+\}/.test(col.storagePath)) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": remote collections must have a static storagePath with no template variables (found "${col.storagePath}")`,
        )
      }
      if (col.pushOnly) {
        errors.push(`${scopeLabel}Collection "${col.name}": remote collections cannot be pushOnly`)
      }
      if (col.bundle) {
        errors.push(`${scopeLabel}Collection "${col.name}": remote collections cannot be part of a bundle`)
      }
      if (col.encryption === ENCRYPTION_DELEGATED) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": remote collections cannot use delegated encryption (server cannot replicate opaque client-encrypted blobs)`,
        )
      }
      if (
        (col.remote.writeMode === "push_through" || col.remote.writeMode === "bidirectional") &&
        !col.remote.pushPath
      ) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": write_mode "${col.remote.writeMode}" requires remote.push_path to be set`,
        )
      }
    }
  }

  // Check bundles: all collections in same bundle must share storagePath
  const bundles = new Map<string, string>()
  for (const col of collections) {
    if (!col.bundle) continue
    const existing = bundles.get(col.bundle)
    if (existing && existing !== col.storagePath) {
      errors.push(
        `${scopeLabel}Bundle "${col.bundle}": all collections must share the same storagePath (found "${existing}" and "${col.storagePath}")`,
      )
    }
    bundles.set(col.bundle, col.storagePath)
  }

  return errors
}

export function validateConfig(config: SyncConfig): string[] {
  const errors: string[] = []

  errors.push(...validateCollections(config.collections, ""))

  if (config.namespaces) {
    for (const [nsName, nsConfig] of Object.entries(config.namespaces)) {
      if (!NAMESPACE_NAME_RE.test(nsName)) {
        errors.push(
          `Namespace "${nsName}": name must only contain letters, digits, hyphens, and underscores`,
        )
      }
      if (RESERVED_NAMESPACE_NAMES.has(nsName)) {
        errors.push(
          `Namespace "${nsName}": name is reserved and cannot be used as a namespace`,
        )
      }
      if (nsConfig.collections.length === 0) {
        errors.push(`Namespace "${nsName}": must contain at least one collection`)
      }
      errors.push(...validateCollections(nsConfig.collections, `Namespace "${nsName}": `))
    }
  }

  return errors
}
