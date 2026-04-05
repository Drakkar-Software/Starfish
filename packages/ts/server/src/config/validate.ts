import type { SyncConfig } from "./schema.js"
import { IDENTITY_PARAM } from "../constants.js"

export function validateConfig(config: SyncConfig): string[] {
  const errors: string[] = []
  const names = new Set<string>()
  const paths = new Set<string>()

  for (const col of config.collections) {
    if (names.has(col.name)) {
      errors.push(`Duplicate collection name: ${col.name}`)
    }
    names.add(col.name)

    if (paths.has(col.storagePath)) {
      errors.push(`Duplicate storage path: ${col.storagePath}`)
    }
    paths.add(col.storagePath)

    if (col.pullOnly && col.pushOnly) {
      errors.push(`Collection "${col.name}" cannot be both pullOnly and pushOnly`)
    }

    if (col.encryption === "identity" && !col.storagePath.includes(IDENTITY_PARAM)) {
      errors.push(
        `Collection "${col.name}" uses identity encryption but storagePath does not contain ${IDENTITY_PARAM}`,
      )
    }

    if (col.bundle) {
      if (col.allowedMimeTypes && col.allowedMimeTypes.length > 0) {
        const isJson =
          col.allowedMimeTypes.length === 1 && col.allowedMimeTypes[0] === "application/json"
        if (!isJson) {
          errors.push(`Bundled collection "${col.name}" cannot use non-JSON MIME types`)
        }
      }
    }

    if (
      col.allowedMimeTypes &&
      col.allowedMimeTypes.length > 0 &&
      !(col.allowedMimeTypes.length === 1 && col.allowedMimeTypes[0] === "application/json")
    ) {
      if (col.encryption === "identity" || col.encryption === "server") {
        errors.push(
          `Binary collection "${col.name}" cannot use "${col.encryption}" encryption`,
        )
      }
      if (col.objectSchema) {
        errors.push(`Binary collection "${col.name}" cannot have objectSchema`)
      }
    }

    if (col.remote) {
      if (col.storagePath.includes(IDENTITY_PARAM)) {
        errors.push(
          `Remote collection "${col.name}" cannot use template variables in storagePath`,
        )
      }
      if (col.pushOnly) {
        errors.push(`Remote collection "${col.name}" cannot be pushOnly`)
      }
      if (col.encryption === "delegated") {
        errors.push(`Remote collection "${col.name}" cannot use delegated encryption`)
      }
      if (
        col.remote.syncTriggers?.includes("webhook") &&
        !col.remote.webhookSecret
      ) {
        errors.push(
          `Remote collection "${col.name}" uses webhook trigger but no webhookSecret`,
        )
      }
      const wm = col.remote.writeMode ?? "pull_only"
      if (
        (wm === "push_through" || wm === "bidirectional") &&
        !col.remote.pushPath
      ) {
        errors.push(
          `Remote collection "${col.name}" with writeMode "${wm}" requires pushPath`,
        )
      }
    }
  }

  return errors
}
