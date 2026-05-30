import type { SyncConfig, CollectionConfig, RateLimitConfig, RateLimitRule } from "./schema.js"
import { ROLE_PUBLIC, ROLE_SELF } from "../constants.js"

const MIME_JSON = "application/json"

const RATE_LIMIT_ACTIONS = ["push", "pull", "list"] as const

/** Validate a collection's `rateLimit` block: positive numeric fields, a valid
 *  `bucket` mode, and that every explicit per-action rule resolves both a
 *  `windowMs` and a `maxRequests` from rule → flat collection fields → global. */
function validateRateLimit(
  col: CollectionConfig,
  scopeLabel: string,
  globalRl: RateLimitConfig | undefined,
  errors: string[],
): void {
  const rl = col.rateLimit
  if (rl == null) return
  const isPosInt = (n: number | undefined): boolean => n == null || (Number.isInteger(n) && n > 0)
  const checkBucket = (b: string | undefined, where: string): void => {
    if (b != null && b !== "identity" && b !== "ip" && b !== "identity+ip") {
      errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.${where}bucket must be "identity", "ip", or "identity+ip", got "${b}"`)
    }
  }

  if (!isPosInt(rl.windowMs)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.windowMs must be a positive integer`)
  if (!isPosInt(rl.maxRequests)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.maxRequests must be a positive integer`)
  checkBucket(rl.bucket, "")

  for (const action of RATE_LIMIT_ACTIONS) {
    const rule: RateLimitRule | undefined = rl[action]
    if (rule == null) continue
    if (!isPosInt(rule.windowMs)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.${action}.windowMs must be a positive integer`)
    if (!isPosInt(rule.maxRequests)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.${action}.maxRequests must be a positive integer`)
    checkBucket(rule.bucket, `${action}.`)

    const twoIndependent = rule.identity != null || rule.ip != null
    if (twoIndependent && rule.bucket != null) {
      errors.push(
        `${scopeLabel}Collection "${col.name}": rateLimit.${action} cannot set both "bucket" and an "identity"/"ip" sub-limit — use one form or the other`,
      )
    }

    if (twoIndependent) {
      // Two-independent form: each present dimension must resolve windowMs + maxRequests.
      for (const dimName of ["identity", "ip"] as const) {
        const dim = rule[dimName]
        if (dim == null) continue
        if (!isPosInt(dim.windowMs)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.${action}.${dimName}.windowMs must be a positive integer`)
        if (!isPosInt(dim.maxRequests)) errors.push(`${scopeLabel}Collection "${col.name}": rateLimit.${action}.${dimName}.maxRequests must be a positive integer`)
        const windowMs = dim.windowMs ?? rule.windowMs ?? rl.windowMs ?? globalRl?.windowMs
        const maxRequests = dim.maxRequests ?? rule.maxRequests ?? rl.maxRequests ?? globalRl?.maxRequests
        if (windowMs == null || maxRequests == null) {
          errors.push(
            `${scopeLabel}Collection "${col.name}": rateLimit.${action}.${dimName} must resolve both windowMs and maxRequests — set them on the dimension, the rule, the collection's rateLimit, or the global rateLimit`,
          )
        }
      }
    } else {
      // Single-counter form.
      const windowMs = rule.windowMs ?? rl.windowMs ?? globalRl?.windowMs
      const maxRequests = rule.maxRequests ?? rl.maxRequests ?? globalRl?.maxRequests
      if (windowMs == null || maxRequests == null) {
        errors.push(
          `${scopeLabel}Collection "${col.name}": rateLimit.${action} must resolve both windowMs and maxRequests — set them on the rule, on the collection's rateLimit, or on the global rateLimit`,
        )
      }
    }
  }
}

const NAMESPACE_NAME_RE = /^[a-zA-Z0-9_-]+$/
// `list` joins `pull`/`push` as a reserved action prefix: the batch-pull route
// detector treats a leading `pull`/`push`/`list` segment as an action (not a
// namespace), so a namespace named `list` would not be recognized as carrying a
// `/list/batch/pull` batch route. Reserving it keeps the detector unambiguous.
const RESERVED_NAMESPACE_NAMES = new Set(["pull", "push", "list", "health", "batch"])

function isBinaryCollection(allowedMimeTypes: string[]): boolean {
  return !allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}

function validateCollections(
  collections: CollectionConfig[],
  scopeLabel: string,
  globalRl?: RateLimitConfig,
): string[] {
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
      const isPosInt = (n: number | undefined): boolean => n == null || (Number.isInteger(n) && n > 0)
      if (!isPosInt(col.appendOnly.maxItems)) {
        errors.push(`${scopeLabel}Collection "${col.name}": appendOnly.maxItems must be a positive integer`)
      }
      if (!isPosInt(col.appendOnly.chunkSize)) {
        errors.push(`${scopeLabel}Collection "${col.name}": appendOnly.chunkSize must be a positive integer`)
      }
      if (persist === false) {
        if (col.appendOnly.maxItems != null) {
          errors.push(`${scopeLabel}Collection "${col.name}": appendOnly.maxItems requires persist=true (nothing is stored when persist=false)`)
        }
        if (col.appendOnly.chunkSize != null) {
          errors.push(`${scopeLabel}Collection "${col.name}": appendOnly.chunkSize requires persist=true (nothing is stored when persist=false)`)
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

    validateRateLimit(col, scopeLabel, globalRl, errors)
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

    // Any IP-dependent bucketing relies on a client IP. In the TypeScript/Hono server
    // there is no portable socket IP, so without an X-Forwarded-For header the ip part
    // collapses to the shared "anonymous" bucket — turning a per-IP limit into a global one.
    const rl = col.rateLimit
    const ruleUsesIp = (r: { bucket?: string; ip?: unknown } | undefined): boolean =>
      r != null && (r.bucket === "ip" || r.bucket === "identity+ip" || r.ip != null)
    const usesIpBucket =
      rl != null &&
      (rl.bucket === "ip" || rl.bucket === "identity+ip" ||
        ruleUsesIp(rl.push) || ruleUsesIp(rl.pull) || ruleUsesIp(rl.list))
    if (usesIpBucket) {
      warnings.push(
        `${scopeLabel}Collection "${col.name}": rateLimit uses IP-based bucketing (bucket "ip"/"identity+ip" or an "ip" sub-limit). The TypeScript server has no portable socket IP — without an X-Forwarded-For header the ip part collapses to a shared "anonymous" bucket (a per-IP limit becomes global). Run behind a proxy that sets X-Forwarded-For.`,
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
  const errors = validateCollections(config.collections, "", config.rateLimit)

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
      errors.push(...validateCollections(nsConfig.collections, `Namespace "${nsName}": `, config.rateLimit))
    }
  }

  return errors
}
