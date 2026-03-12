/** Push conflict error (HTTP 409). */
export class ConflictError extends Error {
  constructor() {
    super("hash_mismatch")
    this.name = "ConflictError"
  }
}

/** HTTP error from the Starfish server. */
export class StarfishHttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string
  ) {
    super(`HTTP ${status}: ${body}`)
    this.name = "StarfishHttpError"
  }
}

/**
 * Auth provider: returns headers to include in requests.
 * Called for every authenticated request (pull and push).
 */
export type AuthProvider = (req: {
  method: string
  path: string
  body: string | null
}) => Record<string, string> | Promise<Record<string, string>>

/** Options for creating a StarfishClient. */
export interface StarfishClientOptions {
  /** Base URL of the Starfish server (e.g. "https://api.example.com/v1"). */
  baseUrl: string
  /** Auth provider that returns headers for authenticated requests. Optional for public-read collections. */
  auth?: AuthProvider
  /** Optional fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch
}

/** Conflict resolver: given local and remote data, return merged result. */
export type ConflictResolver = (
  local: Record<string, unknown>,
  remote: Record<string, unknown>
) => Record<string, unknown>
