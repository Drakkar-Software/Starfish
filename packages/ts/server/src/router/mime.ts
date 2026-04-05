const MIME_JSON = "application/json"

function mimeMatch(mediaType: string, pattern: string): boolean {
  const [type, subtype] = mediaType.split("/")
  const [pType, pSubtype] = pattern.split("/")
  if (!type || !subtype || !pType || !pSubtype) return false
  if (pType !== "*" && pType !== type) return false
  if (pSubtype !== "*" && pSubtype !== subtype) return false
  return true
}

export function matchesAllowedMime(contentType: string, patterns: string[]): boolean {
  const mediaType = contentType.split(";")[0]!.trim().toLowerCase()
  if (!mediaType) return false
  return patterns.some((p) => mimeMatch(mediaType, p.toLowerCase()))
}

export function isJsonCollection(allowedMimeTypes: string[]): boolean {
  return allowedMimeTypes.some((m) => m.toLowerCase() === MIME_JSON)
}
