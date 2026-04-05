export class StartupError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "StartupError"
  }
}

export class AuthError extends Error {
  readonly status: number
  constructor(message: string, status = 403) {
    super(message)
    this.name = "AuthError"
    this.status = status
  }
}

export class ConflictError extends Error {
  readonly docId: string
  constructor(docId: string) {
    super(`Conflict on document: ${docId}`)
    this.name = "ConflictError"
    this.docId = docId
  }
}

export class NotFoundError extends Error {
  readonly key: string
  constructor(key: string) {
    super(`Key not found: ${key}`)
    this.name = "NotFoundError"
    this.key = key
  }
}
