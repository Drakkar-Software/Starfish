/**
 * `@drakkar.software/starfish-replica` — pluggable replication scheduler.
 *
 * Public surface: `ReplicaManager` (the scheduler — interval loop, on_pull
 * cooldown, error funnel), the `ReplicaChannel` seam (`sync(ctx)`) it drives,
 * `HttpReplicaChannel` (the default primary→replica-server HTTP path, built
 * automatically by `new ReplicaManager(store, collections, opts)`), the
 * replica config types (`RemoteConfig`/`WriteMode`/`SyncTrigger`/
 * `RemoteCollection`), `validateReplicaConfig`, and
 * `createReplicaServerPlugin` — a `ServerPlugin` whose `beforePull`/
 * `interceptPush` hooks enforce write modes and proxy push-through writes on
 * the HTTP path, and whose `shutdown` hook stops the sync timers. For
 * authenticated replicas, `createReplicaAuth` builds a signing `fetch` wrapper
 * that signs each outgoing pull/push request with a self-signed device cap-cert.
 *
 * A second data path — replicating a local source into a Starfish space
 * (rather than a local `ObjectStore`) — lives at the `./space` subpath so a
 * client bundle never pulls in `starfish-server`. See `./space/index.js`.
 */

export { ReplicaManager } from "./manager.js"
export { ChannelScheduler } from "./scheduler.js"
export type { ChannelSchedulerEntry } from "./scheduler.js"
export type { WriteMode, SyncTrigger, RemoteConfig, RemoteCollection } from "./config.js"
export type { ReplicaCallContext, ReplicaChannel, ChannelSchedule, ScheduledChannel } from "./channel.js"
export { REPLICATOR_CTX } from "./channel.js"
export { HttpReplicaChannel } from "./http-channel.js"
export { validateReplicaConfig } from "./validate.js"
export { createReplicaServerPlugin } from "./plugin.js"
export type { ReplicaPluginOptions, ReplicaServerPlugin } from "./plugin.js"
export { createReplicaAuth } from "./auth.js"
export type { ReplicaAuth, ReplicaAuthOptions } from "./auth.js"
