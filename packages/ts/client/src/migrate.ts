/** A function that migrates data from one schema version to the next. */
export type MigrationFn = (data: Record<string, unknown>) => Record<string, unknown>

export interface MigrationConfig {
  /** The current schema version of the application. */
  currentVersion: number
  /** Map of version number to the migration that upgrades FROM that version. */
  migrations: Record<number, MigrationFn>
}

/**
 * Creates a migration runner that upgrades documents to the current schema version.
 *
 * Given a document with `_schemaVersion`, applies each migration in sequence
 * until the document reaches `currentVersion`. Throws if the document version
 * is ahead of the app (forward compatibility guard).
 */
export function createMigrator(
  config: MigrationConfig,
): (data: Record<string, unknown>) => Record<string, unknown> {
  // Eagerly validate the migration chain
  for (let v = 1; v < config.currentVersion; v++) {
    if (!config.migrations[v]) {
      throw new Error(`Missing migration for version ${v} -> ${v + 1}`)
    }
  }

  return (data) => {
    const version = typeof data._schemaVersion === "number" ? data._schemaVersion : 1

    if (version > config.currentVersion) {
      throw new Error(
        `Document schema version ${version} is newer than app version ${config.currentVersion}. Update the app.`,
      )
    }

    if (version === config.currentVersion) return data

    let result = { ...data }
    for (let v = version; v < config.currentVersion; v++) {
      const fn = config.migrations[v]
      if (!fn) {
        throw new Error(`Missing migration for version ${v} -> ${v + 1}`)
      }
      try {
        result = fn(result)
      } catch (err) {
        throw new Error(
          `Migration from version ${v} to ${v + 1} failed: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        )
      }
    }
    result._schemaVersion = config.currentVersion
    return result
  }
}
