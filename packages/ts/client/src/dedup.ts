/**
 * Request deduplication: prevents multiple concurrent identical GET requests.
 * If a GET request is in-flight for a URL, subsequent identical GET requests
 * return the same Promise. POST/PUT/DELETE/PATCH are never deduped.
 */
export function createDedupFetch(
  baseFetch: typeof globalThis.fetch = globalThis.fetch.bind(globalThis),
): typeof globalThis.fetch {
  const inflightGets = new Map<string, Promise<Response>>()

  return (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const method = (init?.method ?? "GET").toUpperCase()

    // Only dedup GET requests
    if (method !== "GET") {
      return baseFetch(input, init)
    }

    const url = typeof input === "string"
      ? input
      : input instanceof URL
        ? input.toString()
        : (input as Request).url

    const existing = inflightGets.get(url)
    if (existing) {
      // Return a clone — the original is reserved for cloning only
      return existing.then((res) => res.clone())
    }

    // Store a promise that resolves to a response we keep solely for cloning.
    // The first caller also gets a clone, ensuring the "master" body is never consumed.
    const promise = baseFetch(input, init)
      .then((res) => res)
      .finally(() => {
        inflightGets.delete(url)
      })

    inflightGets.set(url, promise)

    // First caller also gets a clone so the cached response body stays unconsumed
    return promise.then((res) => res.clone())
  }) as typeof globalThis.fetch
}
