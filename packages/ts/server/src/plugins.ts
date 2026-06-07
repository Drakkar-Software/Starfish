/**
 * Server plugin contract.
 *
 * Plugins are the extension mechanism for `createCapCertRoleResolver`: each
 * plugin contributes one or more **per-kind cap-cert validators** that run
 * after the core signature + clock-skew + well-formedness checks. The
 * resolver itself stays cap-kind-agnostic; the application wires together
 * the kinds it wants to support.
 *
 * Plugin validation is additive AND gating:
 *   - The inline `assertCapCertWellFormed` check (run by `verifyCapCert`)
 *     is the baseline; plugins layer **additional** kind-specific checks.
 *   - Strict-kind dispatch is **always** active (secure by default): a cap
 *     whose `kind` has no registered validator is rejected with HTTP 401.
 *   - When `plugins` is omitted from `createCapCertRoleResolver`, the
 *     built-in `defaultServerPlugin` (device-only) is used — so `device`
 *     caps are accepted (baseline is sufficient for an issuer proxy) but
 *     `member` caps are rejected until the app wires a validator that
 *     enforces the member-cap shape rules (`sharingServerPlugin`).
 *
 * The baseline `assertCapCertWellFormed` only checks the generic iss/sub
 * userId relations — it does NOT enforce the member-cap structural barriers
 * (`member-self`, `member-private-path`, `!<col>/_keyring`, …). Those live in
 * `assertMemberCapShape` (`@drakkar.software/starfish-sharing`) and reach the
 * resolver only through `sharingServerPlugin`. Accepting `member` caps without
 * that plugin would bypass every member barrier, so the resolver refuses them.
 */

import type {
  CapCertValidator,
  CapKind,
  ServerPlugin,
  WriteEvent,
  PullHookContext,
  PullHookResult,
  PushHookContext,
  PushHookResult,
  AuthorizeContext,
  AuthorizeResult,
} from "@drakkar.software/starfish-protocol"

export type {
  CapCertValidator,
  ServerPlugin,
  WriteEvent,
  AfterWriteHook,
  AuthorizeContext,
  AuthorizeResult,
  AuthorizeHook,
} from "@drakkar.software/starfish-protocol"

/**
 * Built-in **device-only** plugin. This is the resolver's default when no
 * `plugins` are supplied.
 *
 * It registers a single no-op `"device"` validator: a device cap is a proxy
 * for its issuer, so the baseline `assertCapCertWellFormed` (iss/sub userId
 * relations) plus the resolver's signature / window / nonce / revocation /
 * scope checks fully bound it — there is no additional device-cap shape rule.
 *
 * It deliberately does **not** register `"member"`. Member caps carry
 * structural barriers (`member-self`, `member-private-path`,
 * `!<col>/_keyring`, …) that live in `assertMemberCapShape`
 * (`@drakkar.software/starfish-sharing`). To accept member caps, install
 * `sharingServerPlugin` alongside this one:
 *
 * ```ts
 * createCapCertRoleResolver({
 *   nonceCache, revocationStore,
 *   plugins: [defaultServerPlugin, sharingServerPlugin],
 * })
 * ```
 */
export const defaultServerPlugin: ServerPlugin = {
  name: "default",
  capValidators: {
    device: () => {
      /* device caps are fully bounded by the baseline well-formedness check
         and the resolver's signature/window/nonce/revocation/scope checks;
         no additional device-cap shape rule exists. */
    },
  },
}

/**
 * Compose a list of plugins into a single `kind → ordered validators` map.
 * Order is preserved so multiple plugins registering the same kind run in
 * plugin-list order.
 */
export function composePluginValidators(
  plugins: ServerPlugin[],
): Map<CapKind, CapCertValidator[]> {
  const out = new Map<CapKind, CapCertValidator[]>()
  for (const p of plugins) {
    if (!p.capValidators) continue
    for (const [kind, validator] of Object.entries(p.capValidators) as [
      CapKind,
      CapCertValidator,
    ][]) {
      if (validator === undefined) continue
      const list = out.get(kind) ?? []
      list.push(validator)
      out.set(kind, list)
    }
  }
  return out
}

/**
 * Dispatch a `WriteEvent` to every plugin's `afterWrite` hook, in plugin-list
 * order. Each hook is awaited; a throw is logged and swallowed so one failing
 * side effect (e.g. a queue outage) never breaks the client write or blocks
 * the remaining hooks. No-op when `plugins` is undefined/empty.
 */
export async function dispatchAfterWrite(
  plugins: ServerPlugin[] | undefined,
  event: WriteEvent,
): Promise<void> {
  if (!plugins) return
  for (const p of plugins) {
    if (!p.afterWrite) continue
    try {
      await p.afterWrite(event)
    } catch (e) {
      console.warn(`[Starfish] afterWrite hook "${p.name}" failed:`, e)
    }
  }
}

/**
 * Run every plugin's `beforePull` hook (in plugin-list order) and return the
 * first non-`proceed` directive, or `{ action: "proceed" }` if all proceed.
 * Used by the pull route to let an extension reject the pull (e.g. a write-only
 * replica) or run a side effect first (e.g. a replica sync). A throw propagates
 * — unlike `afterWrite`, a `beforePull` failure must surface (it gates the read).
 */
export async function dispatchBeforePull(
  plugins: ServerPlugin[] | undefined,
  ctx: PullHookContext,
): Promise<PullHookResult> {
  if (!plugins) return { action: "proceed" }
  for (const p of plugins) {
    if (!p.beforePull) continue
    const result = await p.beforePull(ctx)
    if (result.action !== "proceed") return result
  }
  return { action: "proceed" }
}

/**
 * Run every plugin's `interceptPush` hook (in plugin-list order) and return the
 * first non-`proceed` directive (`reject` or `respond`), or
 * `{ action: "proceed" }` if all proceed. Used by the push route to let an
 * extension reject the push or respond on its behalf (e.g. proxy to a primary).
 */
export async function dispatchInterceptPush(
  plugins: ServerPlugin[] | undefined,
  ctx: PushHookContext,
): Promise<PushHookResult> {
  if (!plugins) return { action: "proceed" }
  for (const p of plugins) {
    if (!p.interceptPush) continue
    const result = await p.interceptPush(ctx)
    if (result.action !== "proceed") return result
  }
  return { action: "proceed" }
}

/** True when any plugin contributes an `authorize` hook. Lets the router skip
 *  the anonymous fast-path only when a restriction policy is actually wired,
 *  preserving current behavior for servers that don't use restrictions. */
export function hasAuthorizeHook(plugins: ServerPlugin[] | undefined): boolean {
  return !!plugins?.some((p) => p.authorize)
}

/**
 * Run every plugin's `authorize` hook (in plugin-list order) and return the
 * first `reject` directive, or `{ action: "proceed" }` if all proceed. Fired at
 * the central authorization gate for every action (pull/push/list, incl.
 * batch/bundle members), after roles are resolved. A throw propagates — like
 * `beforePull`, an `authorize` failure must surface (it gates access).
 */
export async function dispatchAuthorize(
  plugins: ServerPlugin[] | undefined,
  ctx: AuthorizeContext,
): Promise<AuthorizeResult> {
  if (!plugins) return { action: "proceed" }
  for (const p of plugins) {
    if (!p.authorize) continue
    const result = await p.authorize(ctx)
    if (result.action !== "proceed") return result
  }
  return { action: "proceed" }
}
