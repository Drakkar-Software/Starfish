import type {
  ServerPlugin,
  AuthorizeContext,
  AuthorizeResult,
  SyncConfig,
  IdentityRestriction,
} from "@drakkar.software/starfish-server"

/** An action a restriction rule can be scoped to. */
export type RestrictionAction = "pull" | "push" | "list"

/**
 * Source of identities for a rule: either a static array, or a callback invoked
 * per request with the {@link AuthorizeContext}. The callback may be async (e.g.
 * read a denylist from a store or remote service). Callbacks should be fast and
 * idempotent — the authorize hook runs on every action, including each member of
 * a batch/bundle request.
 */
export type IdentitySource =
  | string[]
  | ((ctx: AuthorizeContext) => string[] | Promise<string[]>)

/** Narrows which requests a {@link RestrictionRule} applies to. An omitted field
 *  matches everything; an empty scope (or no scope) makes the rule server-wide. */
export interface RestrictionScope {
  /** Only requests in this namespace. Use `null` to target the root (un-namespaced)
   *  collections specifically; omit to match any namespace. */
  namespace?: string | null
  /** Only requests for this collection (by name). Omit to match any collection. */
  collection?: string
  /** Only this action. Omit to match any action. */
  action?: RestrictionAction
}

/**
 * One restriction rule. `mode: "deny"` blocks the listed identities; `mode:
 * "allow"` permits ONLY the listed identities (everyone else — including
 * anonymous callers — is blocked) for the rule's scope. When multiple rules
 * apply to a request, **deny wins**, and the caller must satisfy *every*
 * applicable allow rule.
 */
export interface RestrictionRule {
  mode: "deny" | "allow"
  identities: IdentitySource
  scope?: RestrictionScope
}

export interface RestrictionsPluginOptions {
  /** Runtime rules — static arrays or callbacks. Evaluated alongside any rules
   *  derived from `config`. */
  rules?: RestrictionRule[]
  /** When provided, the static `restrictions` declared in the serializable
   *  `SyncConfig` (at the server, namespace, and collection levels) are compiled
   *  into rules and enforced too. See {@link restrictionsFromConfig}. */
  config?: SyncConfig
  /** HTTP status used when a rule rejects. Defaults to `403`. */
  status?: number
  /** Error message used when a rule rejects. Defaults to `"identity restricted"`. */
  error?: string
}

const DEFAULT_STATUS = 403
const DEFAULT_ERROR = "identity restricted"

/**
 * Compile the static `restrictions` declared throughout a {@link SyncConfig}
 * into {@link RestrictionRule}s. A server-level restriction becomes a
 * server-wide rule; a namespace-level one is scoped to that namespace; a
 * collection-level one is scoped to that collection (and its namespace, if any).
 * A restriction listing `actions` expands to one rule per action.
 */
export function restrictionsFromConfig(config: SyncConfig): RestrictionRule[] {
  const rules: RestrictionRule[] = []

  const expand = (
    restriction: IdentityRestriction,
    base: RestrictionScope,
  ): void => {
    const actions = restriction.actions?.length ? restriction.actions : [undefined]
    for (const action of actions) {
      const scope: RestrictionScope = { ...base }
      if (action != null) scope.action = action
      rules.push({
        mode: restriction.mode,
        identities: [...restriction.identities],
        ...(Object.keys(scope).length > 0 && { scope }),
      })
    }
  }

  for (const r of config.restrictions ?? []) expand(r, {})

  for (const col of config.collections) {
    for (const r of col.restrictions ?? []) expand(r, { namespace: null, collection: col.name })
  }

  for (const [nsName, ns] of Object.entries(config.namespaces ?? {})) {
    for (const r of ns.restrictions ?? []) expand(r, { namespace: nsName })
    for (const col of ns.collections) {
      for (const r of col.restrictions ?? []) {
        expand(r, { namespace: nsName, collection: col.name })
      }
    }
  }

  return rules
}

/** True when `rule.scope` matches the request described by `ctx`. */
function ruleApplies(rule: RestrictionRule, ctx: AuthorizeContext): boolean {
  const s = rule.scope
  if (!s) return true
  if (s.action != null && s.action !== ctx.action) return false
  if (s.collection != null && s.collection !== ctx.collection) return false
  if (s.namespace !== undefined) {
    // `null` targets the root (un-namespaced) collections; a string targets that
    // namespace. `ctx.namespace` is undefined for root requests.
    const want = s.namespace === null ? undefined : s.namespace
    if (want !== ctx.namespace) return false
  }
  return true
}

async function resolveIdentities(
  source: IdentitySource,
  ctx: AuthorizeContext,
): Promise<string[]> {
  return typeof source === "function" ? source(ctx) : source
}

/**
 * Build a {@link ServerPlugin} that denies access by identity. Install it
 * alongside your other plugins in `SyncRouterOptions.plugins`:
 *
 * ```ts
 * const router = createSyncRouter({
 *   store, config, roleResolver,
 *   plugins: [
 *     defaultServerPlugin,
 *     createRestrictionsPlugin({
 *       config, // enforce static `restrictions` from the config
 *       rules: [
 *         { mode: "deny", identities: ["evil-user"] }, // server-wide
 *         { mode: "deny", identities: async (c) => loadBanned(c.collection),
 *           scope: { collection: "notes", action: "push" } },
 *       ],
 *     }),
 *   ],
 * })
 * ```
 *
 * Evaluation: **deny wins** — if any applicable `deny` rule lists the caller,
 * the request is rejected. Otherwise the caller must be listed in *every*
 * applicable `allow` rule (an `allow` rule permits only its listed identities).
 */
export function createRestrictionsPlugin(
  opts: RestrictionsPluginOptions,
): ServerPlugin {
  const status = opts.status ?? DEFAULT_STATUS
  const error = opts.error ?? DEFAULT_ERROR
  const rules: RestrictionRule[] = [
    ...(opts.config ? restrictionsFromConfig(opts.config) : []),
    ...(opts.rules ?? []),
  ]

  const reject: AuthorizeResult = { action: "reject", status, error }

  return {
    name: "restrictions",
    authorize: async (ctx: AuthorizeContext): Promise<AuthorizeResult> => {
      const identity = ctx.identity
      for (const rule of rules) {
        if (!ruleApplies(rule, ctx)) continue
        const list = await resolveIdentities(rule.identities, ctx)
        if (rule.mode === "deny") {
          if (identity != null && list.includes(identity)) return reject
        } else {
          // allow: only listed identities pass. Anonymous (undefined) never matches.
          if (identity == null || !list.includes(identity)) return reject
        }
      }
      return { action: "proceed" }
    },
  }
}
