/**
 * Minimal structural mirrors of the server's role-enricher contract.
 *
 * These are declared locally instead of imported from
 * `@drakkar.software/starfish-server` on purpose: `starfish-server` dev-depends
 * on this package (its tests use `sharingServerPlugin`), so importing the server
 * package back here closes a workspace dependency cycle. A cycle has no valid
 * topological build order, so under a clean `pnpm -r build` this package's `tsc`
 * can run before the server has emitted its `.d.ts`, failing with TS2307. Keeping
 * the consumed types local removes that build-time coupling (the `plugin.ts`
 * sibling already notes this package needs no runtime server dependency).
 *
 * The shapes are structurally compatible with the server's `AuthResult` /
 * `RoleEnricher` / `ObjectStore`, so an enricher produced here drops straight
 * into a `SyncRouter`'s `roleEnricher`. The enrichers' tests exercise the real
 * server types, so any drift surfaces there.
 */

/** The authenticated caller: a bound identity plus its resolved roles. */
export interface AuthResult {
  identity: string
  roles: string[]
}

/** Grants extra roles for a request, given the caller and the path params. */
export type RoleEnricher = (
  auth: AuthResult,
  params: Record<string, string>,
) => Promise<string[]>

/** The single store capability the registry enricher needs. */
export interface ObjectStore {
  getString(key: string): Promise<string | null>
}
