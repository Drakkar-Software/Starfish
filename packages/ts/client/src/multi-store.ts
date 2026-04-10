// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Serializer/deserializer pair for one slice of application state.
 *
 * `serialize` snapshots the current state into a plain object.
 * `restore` applies a snapshot (potentially from a different app version after migration).
 */
export interface StoreSlice<T = unknown> {
  /**
   * Snapshot the current state of this slice into a serializable value.
   * Called during `serialize()`.
   */
  serialize: () => T
  /**
   * Apply a snapshot to this slice.
   * Called during `restore()` — data may be from an older schema version after migration.
   */
  restore: (data: T) => void
}

/**
 * A versioned backup document produced by `MultiStoreSync.serialize()`.
 * Safe to pass to `store.set()` as the Starfish sync document.
 */
export interface BackupDocument<T = Record<string, unknown>> {
  /** Schema version declared in `createMultiStoreSync`. */
  version: number
  /** Unix timestamp (ms) when this backup was created. */
  timestamp: number
  /** Serialized slice data, keyed by slice name. */
  data: T
}

/**
 * A migration function that transforms data from one version to the next.
 * Receives the full `data` object and must return an updated `data` object.
 * Only the `data` field is passed; `version` and `timestamp` are managed automatically.
 */
export type MultiStoreMigrationFn = (data: Record<string, unknown>) => Record<string, unknown>

export interface MultiStoreSyncOptions<T extends Record<string, unknown>> {
  /**
   * Named slices to include in the backup document.
   * Each slice provides `serialize()` and `restore()` methods.
   *
   * @example
   * ```ts
   * slices: {
   *   tasks: {
   *     serialize: () => taskStore.getState().tasks,
   *     restore: (data) => taskStore.setState({ tasks: data }),
   *   },
   *   settings: {
   *     serialize: () => settingsStore.getState().settings,
   *     restore: (data) => settingsStore.setState({ settings: data }),
   *   },
   * }
   * ```
   */
  slices: { [K in keyof T]: StoreSlice<T[K]> }
  /**
   * Current schema version. Increment when slices are added, renamed, or their shape changes.
   * Used to detect forward-incompatible documents from future app versions.
   */
  version: number
  /**
   * Optional migration chain. Key is the version number that produced the data;
   * value is a function that upgrades it to the next version.
   *
   * Migrations run sequentially from the document version up to the current version.
   *
   * @example
   * ```ts
   * migrations: {
   *   1: (data) => ({ ...data, settings: { ...data.settings, theme: "light" } }),
   *   2: (data) => ({ ...data, tasks: data.todos, todos: undefined }),
   * }
   * ```
   */
  migrations?: Record<number, MultiStoreMigrationFn>
}

/**
 * Returned by `createMultiStoreSync`. Serialize and restore coordinated multi-store state.
 */
export interface MultiStoreSync<T extends Record<string, unknown>> {
  /**
   * Snapshot all slices into a `BackupDocument`.
   * Pass the result to `starfishStore.getState().set(() => multiSync.serialize())`.
   */
  serialize: () => BackupDocument<T>
  /**
   * Apply a `BackupDocument` to all slices, running migrations as needed.
   *
   * Throws if the document version is newer than the current version (forward-incompatible).
   * Silently migrates older documents.
   */
  restore: (doc: BackupDocument) => void
  /** Current schema version as declared in options. */
  readonly version: number
}

// ── Implementation ────────────────────────────────────────────────────────────

/**
 * Creates a multi-store sync coordinator.
 *
 * Collects multiple application stores into a single Starfish sync document,
 * with versioned schema migrations for backward compatibility.
 *
 * ```ts
 * const multiSync = createMultiStoreSync({
 *   slices: {
 *     tasks: {
 *       serialize: () => taskStore.getState().tasks,
 *       restore: (tasks) => taskStore.setState({ tasks }),
 *     },
 *     settings: {
 *       serialize: () => settingsStore.getState().settings,
 *       restore: (settings) => settingsStore.setState({ settings }),
 *     },
 *   },
 *   version: 2,
 *   migrations: {
 *     // data from version 1 → upgrade to version 2
 *     1: (data) => ({ ...data, settings: { ...(data.settings as object), darkMode: false } }),
 *   },
 * })
 *
 * // Push:
 * starfishStore.getState().set(() => multiSync.serialize())
 *
 * // Restore on pull (pass as onRemoteUpdate to createStarfishStore):
 * createStarfishStore({
 *   name: "app",
 *   syncManager,
 *   onRemoteUpdate: (doc) => multiSync.restore(doc as BackupDocument),
 * })
 * ```
 */
export function createMultiStoreSync<T extends Record<string, unknown>>(
  options: MultiStoreSyncOptions<T>,
): MultiStoreSync<T> {
  const { slices, version, migrations = {} } = options

  // Validate migration chain at construction time (fail fast)
  for (const fromVersion of Object.keys(migrations)) {
    const v = Number(fromVersion)
    if (isNaN(v) || v < 1) {
      throw new Error(`Migration key must be a positive integer, got: "${fromVersion}"`)
    }
  }

  function serialize(): BackupDocument<T> {
    const data = {} as T
    for (const key of Object.keys(slices) as Array<keyof T>) {
      data[key] = slices[key].serialize() as T[typeof key]
    }
    return { version, timestamp: Date.now(), data }
  }

  function restore(doc: BackupDocument): void {
    if (typeof doc !== "object" || doc === null) {
      throw new Error("restore: expected a BackupDocument object")
    }

    const docVersion = doc.version ?? 1

    if (typeof docVersion !== "number" || !Number.isInteger(docVersion) || docVersion < 1) {
      throw new Error(`restore: invalid document version: ${String(doc.version)}`)
    }

    if (docVersion > version) {
      throw new Error(
        `restore: document version ${docVersion} is newer than current version ${version}. ` +
        `Update the app to restore this backup.`,
      )
    }

    // Run migrations sequentially from docVersion up to current version
    let data: Record<string, unknown> =
      typeof doc.data === "object" && doc.data !== null
        ? { ...(doc.data as Record<string, unknown>) }
        : {}

    for (let v = docVersion; v < version; v++) {
      const migration = migrations[v]
      if (!migration) continue
      try {
        data = migration(data)
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        throw new Error(`restore: migration from version ${v} to ${v + 1} failed: ${msg}`)
      }
    }

    // Restore each slice
    for (const key of Object.keys(slices) as Array<keyof T>) {
      const sliceData = data[key as string]
      if (sliceData !== undefined) {
        slices[key].restore(sliceData as T[typeof key])
      }
    }
  }

  return { serialize, restore, version }
}
