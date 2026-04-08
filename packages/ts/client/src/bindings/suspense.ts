/**
 * React Suspense integration for Starfish sync data.
 * Creates resources that throw Promises while loading (Suspense protocol).
 */

type SuspenseStatus = "pending" | "resolved" | "rejected"

interface SuspenseResource<T> {
  /** Read the resource value. Throws a Promise while pending (Suspense protocol). */
  read(): T
}

/**
 * Create a Suspense-compatible resource from an async fetcher.
 * The first call to `read()` triggers the fetch. While loading, `read()` throws
 * a Promise (which React Suspense catches to show a fallback). Once resolved,
 * `read()` returns the value synchronously.
 *
 * @example
 * ```tsx
 * const resource = createSuspenseResource(() => syncManager.pull())
 * function MyComponent() {
 *   const data = resource.read() // throws while loading, returns data when ready
 *   return <div>{JSON.stringify(data)}</div>
 * }
 * ```
 */
export function createSuspenseResource<T>(
  fetcher: () => Promise<T>,
): SuspenseResource<T> {
  let status: SuspenseStatus = "pending"
  let result: T
  let error: unknown
  let promise: Promise<void> | null = null

  function init(): Promise<void> {
    if (promise) return promise
    promise = fetcher().then(
      (value) => {
        status = "resolved"
        result = value
      },
      (err) => {
        status = "rejected"
        error = err
      },
    )
    return promise
  }

  return {
    read(): T {
      switch (status) {
        case "pending":
          throw init()
        case "resolved":
          return result
        case "rejected":
          throw error
      }
    },
  }
}
