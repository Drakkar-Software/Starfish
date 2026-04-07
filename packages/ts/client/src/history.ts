export interface Snapshot {
  timestamp: number
  label: string
  data: string
}

export interface SnapshotHistoryOptions {
  /** Maximum number of snapshots to retain. Oldest are trimmed first. Default: 20. */
  maxSnapshots?: number
  /** localStorage key for persistence. Pass to enable auto-save/load. */
  storageKey?: string
}

export class SnapshotHistory {
  private snapshots: Snapshot[] = []
  private readonly maxSnapshots: number
  private readonly storageKey: string | undefined

  constructor(options?: SnapshotHistoryOptions) {
    this.maxSnapshots = options?.maxSnapshots ?? 20
    this.storageKey = options?.storageKey

    if (this.storageKey) {
      try {
        const raw = localStorage.getItem(this.storageKey)
        if (raw) {
          const parsed = JSON.parse(raw)
          if (Array.isArray(parsed)) this.snapshots = parsed
        }
      } catch { /* corrupted or unavailable — start fresh */ }
    }
  }

  /** Take a labeled snapshot of the given data. */
  take(label: string, data: Record<string, unknown>): void {
    this.snapshots.push({
      timestamp: Date.now(),
      label,
      data: JSON.stringify(data),
    })
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots = this.snapshots.slice(-this.maxSnapshots)
    }
    this.persist()
  }

  /** Restore data from a snapshot at the given index. Returns undefined if index is invalid or data is corrupt. */
  restore(index: number): Record<string, unknown> | undefined {
    const snapshot = this.snapshots[index]
    if (!snapshot) return undefined
    try {
      return JSON.parse(snapshot.data)
    } catch {
      return undefined
    }
  }

  /** List available snapshots (metadata only, no data payload). */
  list(): Array<{ timestamp: number; label: string }> {
    return this.snapshots.map(({ timestamp, label }) => ({ timestamp, label }))
  }

  /** Clear all snapshots. */
  clear(): void {
    this.snapshots = []
    this.persist()
  }

  private persist(): void {
    if (!this.storageKey) return
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.snapshots))
    } catch { /* quota exceeded — skip silently */ }
  }
}
