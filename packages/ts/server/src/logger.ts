/** Log levels from least to most severe. */
export type LogLevel = "debug" | "info" | "warn" | "error"

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 }

export interface LogEntry {
  level: LogLevel
  message: string
  timestamp: number
  [key: string]: unknown
}

/** Structured server logger. */
export interface ServerLogger {
  log(entry: LogEntry): void
}

/** Console logger that outputs human-readable messages. */
export function createConsoleLogger(minLevel: LogLevel = "info"): ServerLogger {
  const minOrder = LEVEL_ORDER[minLevel]
  return {
    log(entry) {
      if (LEVEL_ORDER[entry.level] < minOrder) return
      const prefix = `[Starfish:${entry.level.toUpperCase()}]`
      const { level: _, message, timestamp: _ts, ...extra } = entry
      const extraStr = Object.keys(extra).length > 0 ? ` ${JSON.stringify(extra)}` : ""
      const fn = entry.level === "error" ? console.error
        : entry.level === "warn" ? console.warn
        : console.log
      fn(`${prefix} ${message}${extraStr}`)
    },
  }
}

/** JSON-line logger for structured log aggregation (e.g. CloudWatch, Datadog). */
export function createJsonLogger(minLevel: LogLevel = "info"): ServerLogger {
  const minOrder = LEVEL_ORDER[minLevel]
  return {
    log(entry) {
      if (LEVEL_ORDER[entry.level] < minOrder) return
      console.log(JSON.stringify(entry))
    },
  }
}

/** No-op logger (discard all log entries). */
export function createNoopLogger(): ServerLogger {
  return { log() {} }
}
