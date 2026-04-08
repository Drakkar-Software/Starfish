/**
 * Service Worker utilities for offline support and PWA functionality.
 */

export interface ServiceWorkerOptions {
  /** Scope for the service worker registration. */
  scope?: string
  /** Called when an updated service worker is available. */
  onUpdate?: (registration: ServiceWorkerRegistration) => void
}

/** Check if service workers are supported in the current environment. */
export function isServiceWorkerSupported(): boolean {
  return typeof navigator !== "undefined" && "serviceWorker" in navigator
}

/**
 * Register a service worker for offline support.
 * Returns the registration, or null if not supported.
 */
export async function registerServiceWorker(
  scriptUrl: string,
  opts?: ServiceWorkerOptions,
): Promise<ServiceWorkerRegistration | null> {
  if (!isServiceWorkerSupported()) return null

  try {
    const registration = await navigator.serviceWorker.register(scriptUrl, {
      scope: opts?.scope,
    })

    if (opts?.onUpdate) {
      registration.onupdatefound = () => {
        const installingWorker = registration.installing
        if (installingWorker) {
          installingWorker.onstatechange = () => {
            if (
              installingWorker.state === "installed" &&
              navigator.serviceWorker.controller
            ) {
              opts.onUpdate!(registration)
            }
          }
        }
      }
    }

    return registration
  } catch {
    return null
  }
}

/** Unregister all service worker registrations. Returns true if any were unregistered. */
export async function unregisterServiceWorkers(): Promise<boolean> {
  if (!isServiceWorkerSupported()) return false

  try {
    const registrations = await navigator.serviceWorker.getRegistrations()
    let unregistered = false
    for (const registration of registrations) {
      const result = await registration.unregister()
      if (result) unregistered = true
    }
    return unregistered
  } catch {
    return false
  }
}
