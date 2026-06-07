/**
 * `@drakkar.software/starfish-replica` — primary→replica replication extension.
 *
 * Public surface: `ReplicaManager` (the sync engine), the replica config types
 * (`RemoteConfig`/`WriteMode`/`SyncTrigger`/`RemoteCollection`),
 * `validateReplicaConfig`, and `createReplicaServerPlugin` — a `ServerPlugin`
 * whose `beforePull`/`interceptPush` hooks enforce write modes and proxy
 * push-through writes, and whose `shutdown` hook stops the sync timers. For
 * authenticated replicas, `createReplicaAuth` builds a signing `fetch` wrapper
 * that signs each outgoing pull/push request with a self-signed device cap-cert.
 */

export { ReplicaManager } from "./manager.js"
export type { WriteMode, SyncTrigger, RemoteConfig, RemoteCollection } from "./config.js"
export { validateReplicaConfig } from "./validate.js"
export { createReplicaServerPlugin } from "./plugin.js"
export type { ReplicaPluginOptions, ReplicaServerPlugin } from "./plugin.js"
export { createReplicaAuth } from "./auth.js"
export type { ReplicaAuth, ReplicaAuthOptions } from "./auth.js"
