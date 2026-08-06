/**
 * `@drakkar.software/starfish-replica/space` — replicate a local data source
 * into per-collection nodes of one or more Starfish spaces, instead of into a
 * local `starfish-server` `ObjectStore`.
 *
 * Depends on `@drakkar.software/starfish-spaces` (peer dependency) and NEVER
 * imports `@drakkar.software/starfish-server` — safe to bundle into a mobile
 * or browser client, unlike the root `.` entry which is server-oriented.
 * This is also why `ReplicaManager` here is a DIFFERENT class than the root
 * entry's `ReplicaManager`: the root one's back-compat HTTP constructor
 * statically needs `starfish-server`, so importing it always drags that in.
 * This one is the scheduler with no such baggage — same scheduling API
 * (`start`/`stop`/`onPull`/`syncNow`/`syncAll`), just without the HTTP-only
 * `remoteFor`/`proxyPush` methods, which don't apply to space channels anyway.
 *
 * ```ts
 * import { createSpaceMirrorChannel, ReplicaManager } from "@drakkar.software/starfish-replica/space"
 *
 * const channel = createSpaceMirrorChannel({
 *   name: "cloud-mirror",
 *   session,
 *   collections: [{ id: "user-accounts", spaceName: "app-mirror" }],
 *   enabledIds: () => currentlyEnabledCollectionIds(),
 *   readSource: (id) => readLocalCollection(id),
 *   docPath: (spaceId, nodeId) => `spaces/${spaceId}/objects/mirror/${nodeId}`,
 * })
 * const manager = new ReplicaManager([
 *   { channel, schedule: { triggers: ["scheduled"], intervalMs: 5 * 60_000 } },
 * ])
 * manager.start()
 * // ... later, read the last sync's result:
 * channel.result // { spaces, created, written, skipped, cleared }
 * ```
 */

export { ChannelScheduler as ReplicaManager } from "../scheduler.js"
export type { ReplicaCallContext, ReplicaChannel, ChannelSchedule, ScheduledChannel } from "../channel.js"
export { REPLICATOR_CTX } from "../channel.js"

export {
  createSpaceMirrorChannel,
  type SpaceMirrorChannel,
  type SpaceMirrorChannelOptions,
  type SpaceMirrorCollection,
  type SpaceMirrorResult,
} from "./mirror-channel.js"
export { planSpaceMirror, type ExistingSpaceNode, type SpaceMirrorPlan } from "./plan.js"
export {
  defaultSpacePort,
  findOrCreateSpace,
  type CreateNodeInput,
  type NodeAccess,
  type NodeAccessHandle,
  type Session,
  type SpacePort,
} from "./port.js"
export { readSpaceMirror, type ReadSpaceMirrorOptions } from "./reader.js"
