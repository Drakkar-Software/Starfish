/**
 * Audit logging contract (shared by the server host + the audit extension).
 *
 * Defined here in the protocol package — the shared contract layer — so the
 * server host (`starfish-server`) can emit audit events against the
 * `AuditLogger` interface and the extension package (`starfish-audit`) can
 * supply concrete loggers, both without a workspace dependency cycle. The
 * concrete loggers (console / callback / no-op) live in `starfish-audit`.
 */

/** Entry recorded in the audit log. */
export interface AuditEntry {
  timestamp: number
  action: "pull" | "push"
  collection: string
  identity: string | null
  documentKey: string
  success: boolean
  statusCode: number
  params?: Record<string, string>
}

/** Audit logger interface. */
export interface AuditLogger {
  record(entry: AuditEntry): void | Promise<void>
}
