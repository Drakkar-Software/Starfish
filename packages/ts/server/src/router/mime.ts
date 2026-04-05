const MIME_JSON = "application/json"

function minimatch(value: string, pattern: string): boolean {
  const regex = new RegExp(
    "^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$",
  )
  return regex.test(value)
}

export function matchesAllowedMime(contentType: string, patterns: string[]): boolean {
  const mediaType = contentType.split(";")[0].trim().toLowerCase()
  if (!mediaType) return false
  return patterns.some((p) => minimatch(mediaType, p.toLowerCase()))
}

export function isJsonCollection(allowedMimeTypes?: string[]): boolean {
  if (!allowedMimeTypes || allowedMimeTypes.length === 0) return false
  return allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}
