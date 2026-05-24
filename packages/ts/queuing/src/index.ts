/**
 * `@drakkar.software/starfish-queuing` — change-event publishing extension.
 *
 * Public surface: the `Queue` transport interface, the in-process `MemoryQueue`
 * and callback-based `CustomQueue` backends, the `QueueMessage` shape, the
 * per-collection `QueueConfig`, and `createQueuingServerPlugin` — a
 * `ServerPlugin` whose `afterWrite` hook publishes a message after each
 * successful push.
 */

export type { Queue } from "./base.js"
export type { QueueMessage } from "./message.js"
export { MemoryQueue, CustomQueue } from "./memory.js"
export type { QueueConfig } from "./config.js"
export { coerceQueue } from "./config.js"
export { createQueuingServerPlugin } from "./plugin.js"
export type { QueuingPluginOptions } from "./plugin.js"
