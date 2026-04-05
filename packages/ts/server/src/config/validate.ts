import type { SyncConfig } from "./schema.js"
import { IDENTITY_PARAM, CONTENT_TYPE_JSON } from "../constants.js"

const MIME_JSON = CONTENT_TYPE_JSON

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

    if (
      (col.readRoles ?? []).includes("public") &&
      col.encryption === "identity"
    ) {
      errors.push(
        `Collection "${col.name}": public collections must not use "identity" encryption (key would be derived from empty identity)`,
      )
    }

    if (col.bundle && col.encryption !== "identity") {
      errors.push(
        `Collection "${col.name}": bundled collections must use "identity" encryption`,
      )
    }

    if (col.bundle && !col.storagePath.includes(IDENTITY_PARAM)) {
      errors.push(
        `Collection "${col.name}": bundled collections must have ${IDENTITY_PARAM} in storagePath`,
      )
    }

    if (!col.pullOnly && !(col.readRoles && col.readRoles.length > 0)) {
      errors.push(
        `Collection "${col.name}": readRoles must not be empty (use ["public"] for public access)`,
      )
    }

    const allowedMime = col.allowedMimeTypes ?? []
    if (allowedMime.length === 0) {
      errors.push(
        `Collection "${col.name}": allowedMimeTypes must contain at least one pattern`,
      )
    }

    const isBinary = allowedMime.length > 0 && isBinaryCollection(allowedMime)
    if (isBinary) {
      if (col.encryption === "identity" || col.encryption === "server") {
        errors.push(
          `Collection "${col.name}": binary collections cannot use "${col.encryption}" encryption (storage layer is string-based)`,
        )
      }
      if (col.objectSchema) {
        errors.push(
          `Collection "${col.name}": binary collections cannot have objectSchema`,
        )
      }
      if (col.bundle) {
        errors.push(
          `Collection "${col.name}": binary collections cannot be part of a bundle`,
        )
      }
      if (col.remote) {
        errors.push(
          `Collection "${col.name}": binary collections cannot have remote replication`,
        )
      }
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
      if (col.encryption === "delegated") {
        errors.push(
          `Collection "${col.name}": remote collections cannot use delegated encryption (server cannot replicate opaque client-encrypted blobs)`,
        )
      }
      const wm = col.remote.writeMode ?? "pull_only"
      if (
        (wm === "push_through" || wm === "bidirectional") &&
        !col.remote.pushPath
      ) {
        errors.push(
          `Collection "${col.name}": writeMode "${wm}" requires remote.pushPath to be set`,
        )
      }
      if (
        col.remote.syncTriggers?.includes("webhook") &&
        !col.remote.webhookSecret
      ) {
        errors.push(
          `Collection "${col.name}": sync trigger "webhook" requires remote.webhookSecret to be set`,
        )
      }
    }
  }

  // Bundle storagePath consistency
  const bundles: Record<string, string> = {}
  for (const col of config.collections) {
    if (!col.bundle) continue
    const existing = bundles[col.bundle]
    if (existing && existing !== col.storagePath) {
      errors.push(
        `Bundle "${col.bundle}": all collections must share the same storagePath (found "${existing}" and "${col.storagePath}")`,
      )
    }
    bundles[col.bundle] = col.storagePath
  }

  return errors
}
