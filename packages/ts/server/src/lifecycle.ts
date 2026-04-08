import type { ReplicaManager } from "./replica/manager.js"
import type { Queue } from "./queue/base.js"

export interface GracefulShutdownOptions {
  /** Called during shutdown to perform cleanup (e.g. close DB connections). */
  onShutdown?: () => Promise<void>
  /** Maximum time in ms to wait for cleanup before forcing exit. Default: 10000. */
  timeoutMs?: number
  /** ReplicaManager to stop during shutdown. */
  replicaManager?: ReplicaManager
  /** Queue to close during shutdown. */
  queue?: Queue
  /** Signals to listen for. Default: ["SIGTERM", "SIGINT"]. */
  signals?: string[]
}

export interface ShutdownHandle {
  /** Manually trigger shutdown (e.g. from tests). */
  shutdown: () => Promise<void>
  /** Remove signal listeners. */
  unregister: () => void
}

export function createGracefulShutdown(opts: GracefulShutdownOptions = {}): ShutdownHandle {
  const timeoutMs = opts.timeoutMs ?? 10_000
  const signals = opts.signals ?? ["SIGTERM", "SIGINT"]
  let shuttingDown = false

  const shutdown = async (): Promise<void> => {
    if (shuttingDown) return
    shuttingDown = true

    const timer = setTimeout(() => {
      console.error("[Starfish] Graceful shutdown timed out, forcing exit")
      if (typeof process !== "undefined") process.exit(1)
    }, timeoutMs)

    try {
      if (opts.replicaManager) {
        await opts.replicaManager.stop()
      }
      if (opts.queue?.close) {
        await opts.queue.close()
      }
      if (opts.onShutdown) {
        await opts.onShutdown()
      }
    } catch (e) {
      console.error("[Starfish] Error during graceful shutdown:", e)
    } finally {
      clearTimeout(timer)
    }
  }

  const handler = () => {
    shutdown().then(() => {
      if (typeof process !== "undefined") process.exit(0)
    })
  }

  for (const sig of signals) {
    if (typeof process !== "undefined" && process.on) {
      process.on(sig, handler)
    }
  }

  const unregister = (): void => {
    for (const sig of signals) {
      if (typeof process !== "undefined" && process.removeListener) {
        process.removeListener(sig, handler)
      }
    }
  }

  return { shutdown, unregister }
}
