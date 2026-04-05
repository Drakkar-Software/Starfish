export function checkBodyLimit(
  contentLength: string | null | undefined,
  maxBytes: number,
): { error: string; status: number } | null {
  if (contentLength == null) return null
  const parsed = parseInt(contentLength, 10)
  if (isNaN(parsed) || parsed < 0) {
    return { error: "Invalid Content-Length", status: 400 }
  }
  if (parsed > maxBytes) {
    return { error: "Payload too large", status: 413 }
  }
  return null
}

interface BucketEntry {
  count: number
  resetAt: number
}

export class RateLimiter {
  private _windowMs: number
  private _maxRequests: number
  private _buckets = new Map<string, BucketEntry>()

  constructor(windowMs: number = 60_000, maxRequests: number = 100) {
    this._windowMs = windowMs
    this._maxRequests = maxRequests
  }

  check(
    identity: string | null,
    headers?: { get(name: string): string | null | undefined },
  ): { error: string; status: number } | null {
    let bucketKey = identity
    if (!bucketKey && headers) {
      const forwarded = headers.get("x-forwarded-for")
      if (forwarded) {
        bucketKey = forwarded.split(",")[0]!.trim()
      }
    }
    if (!bucketKey) {
      bucketKey = "anonymous"
    }

    const now = Date.now()
    let entry = this._buckets.get(bucketKey)

    if (!entry || entry.resetAt <= now) {
      // Clean up expired entries
      for (const [k, v] of this._buckets) {
        if (v.resetAt <= now) this._buckets.delete(k)
      }
      entry = { count: 0, resetAt: now + this._windowMs }
      this._buckets.set(bucketKey, entry)
    }

    entry.count += 1

    if (entry.count > this._maxRequests) {
      return { error: "Rate limit exceeded", status: 429 }
    }

    return null
  }
}
