/** Validation result: true if valid, or an array of error messages. */
export type ValidationResult = true | string[]

/** A function that validates data before push. */
export type Validator = (data: Record<string, unknown>) => ValidationResult

/** Error thrown when pre-push validation fails. */
export class ValidationError extends Error {
  constructor(public readonly errors: string[]) {
    super(`Validation failed: ${errors.join("; ")}`)
    this.name = "ValidationError"
  }
}

/**
 * Creates a validator from a JSON Schema object.
 * Requires an Ajv-compatible validate function.
 *
 * @example
 * ```ts
 * import Ajv from "ajv"
 * const ajv = new Ajv()
 * const validator = createSchemaValidator(ajv, mySchema)
 * ```
 */
export function createSchemaValidator(
  ajv: { compile: (schema: object) => { (data: unknown): boolean; errors?: unknown }; errorsText: (errors?: unknown) => string },
  schema: object,
): Validator {
  const validate = ajv.compile(schema)
  return (data) => {
    if (validate(data)) return true
    return [ajv.errorsText(validate.errors)]
  }
}
