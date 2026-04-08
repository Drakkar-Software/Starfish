/**
 * Request deduplication: prevents multiple concurrent identical GET requests.
 * If a GET request is in-flight for a URL, subsequent identical GET requests
 * return the same Promise. POST/PUT/DELETE are never deduped.
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

    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url

    const existing = inflightGets.get(url)
    if (existing) {
      // Clone the response so each consumer gets their own body
      return existing.then((res) => res.clone())
    }

    const promise = baseFetch(input, init).then((res) => {
      // Remove from cache once resolved
      inflightGets.delete(url)
      return res
    }).catch((err) => {
      inflightGets.delete(url)
      throw err
    })

    inflightGets.set(url, promise)
    return promise
  }) as typeof globalThis.fetch
}
