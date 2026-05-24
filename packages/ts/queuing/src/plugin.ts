/**
 * Server plugin for the queuing extension.
 *
 * Implements the `afterWrite` write-path hook from the `ServerPlugin` contract:
 * after a successful push the server hands the plugin a `WriteEvent`; for any
 * collection present in the plugin's `collections` map it builds a
 * `QueueMessage` and publishes it to the configured `Queue`. `shutdown` closes
 * the queue during graceful shutdown.
 *
 * The `ServerPlugin`/`WriteEvent` types live in `starfish-protocol` (the shared
 * contract layer), so this package needs no dependency on `starfish-server` —
 * applications wire both packages at the top level.
 */

import type { ServerPlugin, WriteEvent } from "@drakkar.software/starfish-protocol"
import type { Queue } from "./base.js"
import type { QueueMessage } from "./message.js"
import type { QueueConfig } from "./config.js"

export interface QueuingPluginOptions {
  /** Transport the messages are published to (MemoryQueue, CustomQueue, …). */
  queue: Queue
  /** Per-collection config. Collections absent from this map publish nothing. */
  collections: Record<string, QueueConfig>
}

/**
 * Build a `ServerPlugin` that publishes a change event to `queue` after every
 * successful push to a configured collection.
 */
export function createQueuingServerPlugin(opts: QueuingPluginOptions): ServerPlugin {
  const { queue, collections } = opts
  return {
    name: "starfish-queuing",
    afterWrite: async (event: WriteEvent): Promise<void> => {
      const cfg = collections[event.collection]
      if (!cfg) return
      // Coalesce an empty-string topic to the collection name (an empty broker
      // subject is a footgun). `||` rather than `??` so "" falls back too —
      // matches the Python plugin's `config.topic or event.collection`.
      const subject = cfg.topic || event.collection
      const msg: QueueMessage = {
        collection: event.collection,
        hash: event.hash,
        timestamp: event.timestamp,
      }
      if (cfg.includeParams && Object.keys(event.params).length > 0) {
        msg.params = event.params
      }
      if (cfg.includeBody) {
        if (event.body !== undefined) {
          msg.body = event.body
        } else {
          console.warn(
            `[Starfish] includeBody enabled for "${event.collection}" but request data is not a plain object; body omitted from queue message`,
          )
        }
      }
      try {
        await queue.publish(subject, new TextEncoder().encode(JSON.stringify(msg)))
      } catch (e) {
        // Queue errors must not break client writes, but must be visible to operators.
        console.warn(`[Starfish] Failed to publish queue event for "${event.collection}":`, e)
      }
    },
    shutdown: async (): Promise<void> => {
      if (queue.close) await queue.close()
    },
  }
}
