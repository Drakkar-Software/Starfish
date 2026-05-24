import type { SyncConfig, CollectionConfig } from "./schema.js"
import { ROLE_PUBLIC, ROLE_SELF } from "../constants.js"

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

    if (col.appendOnly) {
      const persist = col.appendOnly.persist
      if (col.appendOnly.type !== "by_timestamp") {
        errors.push(`${scopeLabel}Collection "${col.name}": appendOnly.type "${String(col.appendOnly.type)}" is not supported (expected "by_timestamp")`)
      }
      if (isBinaryCollection(col.allowedMimeTypes)) {
        errors.push(`${scopeLabel}Collection "${col.name}": appendOnly cannot be used with binary collections`)
      }
      if (col.pullOnly) {
        errors.push(`${scopeLabel}Collection "${col.name}": appendOnly cannot be used with pullOnly (push routes are disabled)`)
      }
      if (persist !== false) {
        // persist=true (default) — the stored-array path. `delegated` encryption is now
        // supported: each element's `data` is stored opaquely, so the server never reads
        // ciphertext to append (only the plaintext per-element `ts` envelope).
        if (col.bundle) {
          errors.push(`${scopeLabel}Collection "${col.name}": appendOnly with persist=true cannot be used with bundle`)
        }
      }
    }

    if (col.listable) {
      const paramMatches = col.storagePath.match(/\{(\w+)\}/g) ?? []
      if (paramMatches.length === 0) {
        errors.push(`${scopeLabel}Collection "${col.name}": listable requires at least one path parameter in storagePath`)
      } else {
        // Strip a trailing slash before taking the last segment so
        // "users/{identity}/" is treated like "users/{identity}" — matching
        // the Python validator, which does `rstrip("/")`.
        const lastSegment = col.storagePath.replace(/\/+$/, "").split("/").pop() ?? ""
        if (!/^\{[^}]+\}$/.test(lastSegment)) {
          errors.push(`${scopeLabel}Collection "${col.name}": listable requires the last storagePath segment to be a path parameter (e.g. {day}), got "${lastSegment}"`)
        }
      }
      if (col.appendOnly && col.appendOnly.persist === false) {
        errors.push(`${scopeLabel}Collection "${col.name}": listable cannot be used with appendOnly+persist=false (no documents are stored)`)
      }
      if (col.bundle) {
        errors.push(`${scopeLabel}Collection "${col.name}": listable cannot be used with bundle (bundled collections share storage paths)`)
      }
    }

    if (col.rootOnly) {
      if (col.readRoles.includes(ROLE_PUBLIC) || col.writeRoles.includes(ROLE_PUBLIC)) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": rootOnly cannot be combined with the "${ROLE_PUBLIC}" role in readRoles/writeRoles (a root-only collection is never public)`,
        )
      }
    }

    if (!col.pullOnly && col.readRoles.length === 0) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": readRoles must not be empty (use ["${ROLE_PUBLIC}"] for public access)`,
      )
    }

    const isBinary = isBinaryCollection(col.allowedMimeTypes)
    if (isBinary) {
      if (col.objectSchema != null) {
        errors.push(`${scopeLabel}Collection "${col.name}": binary collections cannot have objectSchema`)
      }
      if (col.bundle) {
        errors.push(`${scopeLabel}Collection "${col.name}": binary collections cannot be part of a bundle`)
      }
    }
    if (col.allowedMimeTypes.length === 0) {
      errors.push(`${scopeLabel}Collection "${col.name}": allowedMimeTypes must contain at least one pattern`)
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

const CAP_ROLE_RE = /^cap:(read|write|list):(.+)$/

/**
 * Non-fatal configuration checks. These never block startup (unlike
 * {@link validateConfig}); they surface likely misconfigurations that silently
 * widen access. Callers should log the returned strings.
 *
 *  - A `public` entry in `writeRoles` lets *anonymous* clients write.
 *  - A `cap:<op>:<other>` role naming a DIFFERENT collection is almost always a
 *    copy-paste typo that grants cross-collection access (the cap-resolver
 *    synthesizes `cap:<op>:<collection>` per the cert's scope, so a cap for
 *    "other" would satisfy this collection's gate).
 */
function collectCollectionWarnings(
  collections: CollectionConfig[],
  scopeLabel: string,
): string[] {
  const warnings: string[] = []
  for (const col of collections) {
    if (col.writeRoles?.includes(ROLE_PUBLIC)) {
      warnings.push(
        `${scopeLabel}Collection "${col.name}": writeRoles contains "${ROLE_PUBLIC}" — anonymous clients can WRITE this collection. Remove it unless public writes are intended.`,
      )
    }
    const checkCross = (roles: string[] | undefined, label: string): void => {
      for (const r of roles ?? []) {
        const m = CAP_ROLE_RE.exec(r)
        if (m && m[2] !== col.name && m[2] !== "*") {
          warnings.push(
            `${scopeLabel}Collection "${col.name}": ${label} references "${r}", a cap role scoped to a different collection ("${m[2]}"). A cap-cert for "${m[2]}" would gain access here — did you mean "cap:${m[1]}:${col.name}"?`,
          )
        }
      }
    }
    checkCross(col.readRoles, "readRoles")
    checkCross(col.writeRoles, "writeRoles")

    // The "self" role is granted only when the "{identity}" path param equals
    // the caller. A collection that uses "self" but whose storagePath has no
    // "{identity}" segment (e.g. it used "{owner}"/"{userId}") will NEVER be
    // granted "self" — likely a typo where per-user isolation was intended.
    const usesSelf = col.readRoles?.includes(ROLE_SELF) || col.writeRoles?.includes(ROLE_SELF)
    if (usesSelf && !col.storagePath.includes("{identity}")) {
      warnings.push(
        `${scopeLabel}Collection "${col.name}": uses the "${ROLE_SELF}" role but its storagePath has no "{identity}" segment. "${ROLE_SELF}" is granted only when the "{identity}" path param equals the caller, so it can never be granted here — did you mean to use "{identity}" instead of another param name?`,
      )
    }
  }
  return warnings
}

/**
 * Collect non-fatal configuration warnings (see {@link collectCollectionWarnings}).
 * Returns an empty array for a clean config. Surfaced at load time by the
 * config loader; also exported so apps can lint configs themselves.
 */
export function collectConfigWarnings(config: SyncConfig): string[] {
  const warnings = collectCollectionWarnings(config.collections, "")
  if (config.namespaces) {
    for (const [nsName, nsConfig] of Object.entries(config.namespaces)) {
      warnings.push(...collectCollectionWarnings(nsConfig.collections, `Namespace "${nsName}": `))
    }
  }
  return warnings
}

export function validateConfig(config: SyncConfig): string[] {
  const errors = validateCollections(config.collections, "")

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
