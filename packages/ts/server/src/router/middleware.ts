export function checkBodyLimit(
  contentLength: string | null | undefined,
  maxBytes: number,
): Response | null {
  if (contentLength == null) return null
  const parsed = parseInt(contentLength, 10)
  if (isNaN(parsed) || parsed < 0) {
    return Response.json({ error: "Invalid Content-Length" }, { status: 400 })
  }
  if (parsed > maxBytes) {
    return Response.json({ error: "Payload too large" }, { status: 413 })
  }
  return null
}

interface BucketEntry {
  count: number
  resetAt: number
}

export class RateLimiter {
  private readonly windowMs: number
  private readonly maxRequests: number
  private buckets = new Map<string, BucketEntry>()

  constructor(windowMs = 60_000, maxRequests = 100) {
    this.windowMs = windowMs
    this.maxRequests = maxRequests
  }

  check(identity: string | null | undefined, request?: Request): Response | null {
    let bucketKey = identity
    if (!bucketKey && request) {
      const forwarded = request.headers.get("x-forwarded-for")
      if (forwarded) {
        bucketKey = forwarded.split(",")[0].trim()
      } else {
        bucketKey = "anonymous"
      }
    }
    if (!bucketKey) bucketKey = "anonymous"

    const now = Date.now()
    let entry = this.buckets.get(bucketKey)

    if (!entry || entry.resetAt <= now) {
      for (const [k, v] of this.buckets) {
        if (v.resetAt <= now) this.buckets.delete(k)
      }
      entry = { count: 0, resetAt: now + this.windowMs }
      this.buckets.set(bucketKey, entry)
    }

    entry.count++

    if (entry.count > this.maxRequests) {
      return Response.json({ error: "Rate limit exceeded" }, { status: 429 })
    }

    return null
  }
}
