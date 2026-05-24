import type { AuditEntry, AuditLogger } from "@drakkar.software/starfish-protocol"

/** Audit logger that writes to console. */
export function createConsoleAuditLogger(): AuditLogger {
  return {
    record(entry) {
      const status = entry.success ? "OK" : "FAIL"
      console.log(
        `[Starfish:AUDIT] ${entry.action.toUpperCase()} ${entry.collection} ` +
        `by ${entry.identity ?? "anonymous"} → ${status} (${entry.statusCode})`,
      )
    },
  }
}

/** Audit logger that delegates to a callback. */
export function createCallbackAuditLogger(
  cb: (entry: AuditEntry) => void | Promise<void>,
): AuditLogger {
  return { record: cb }
}

/** No-op audit logger (discards entries). */
export function createNoopAuditLogger(): AuditLogger {
  return { record() {} }
}
