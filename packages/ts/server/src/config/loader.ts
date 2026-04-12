import type { SyncConfig, CollectionConfig, RemoteConfig, QueueConfig, CollectionRateLimitConfig, NamespaceConfig, FieldPermission } from "./schema.js"
import { validateConfig } from "./validate.js"
import { StartupError } from "../errors.js"
import { DEFAULT_CONFIG_KEY, CONTENT_TYPE_JSON } from "../constants.js"
import type { ObjectStore } from "../storage/base.js"

function coerceRateLimit(v: unknown): CollectionRateLimitConfig | null | undefined {
  if (v === true) return {}
  if (v === false) return null
  return v as CollectionRateLimitConfig | null | undefined
}

function coerceQueue(v: unknown): QueueConfig | undefined {
  if (v === true) return { includeParams: false }
  if (v === false || v == null) return undefined
  return v as QueueConfig
}

function parseRemote(raw: Record<string, unknown>): RemoteConfig {
  return {
    url: raw["url"] as string,
    pullPath: raw["pullPath"] as string,
    pushPath: (raw["pushPath"] as string) ?? undefined,
    intervalMs: (raw["intervalMs"] as number) ?? 60_000,
    headers: (raw["headers"] as Record<string, string>) ?? {},
    writeMode: (raw["writeMode"] as RemoteConfig["writeMode"]) ?? "pull_only",
    syncTriggers: (raw["syncTriggers"] as RemoteConfig["syncTriggers"]) ?? ["scheduled"],
    onPullMinIntervalMs: (raw["onPullMinIntervalMs"] as number) ?? undefined,
  }
}

function parseCollection(raw: Record<string, unknown>): CollectionConfig {
  return {
    name: raw["name"] as string,
    storagePath: raw["storagePath"] as string,
    readRoles: raw["readRoles"] as string[],
    writeRoles: raw["writeRoles"] as string[],
    encryption: raw["encryption"] as CollectionConfig["encryption"],
    maxBodyBytes: raw["maxBodyBytes"] as number,
    rateLimit: coerceRateLimit(raw["rateLimit"]),
    cacheDurationMs: (raw["cacheDurationMs"] as number) ?? undefined,
    objectSchema: (raw["objectSchema"] as Record<string, unknown>) ?? undefined,
    allowedMimeTypes: (raw["allowedMimeTypes"] as string[]) ?? ["application/json"],
    pullOnly: (raw["pullOnly"] as boolean) ?? undefined,
    pushOnly: (raw["pushOnly"] as boolean) ?? undefined,
    forceFullFetch: (raw["forceFullFetch"] as boolean) ?? undefined,
    clientEncrypted: (raw["clientEncrypted"] as boolean) ?? undefined,
    bundle: (raw["bundle"] as string) ?? undefined,
    remote: raw["remote"] ? parseRemote(raw["remote"] as Record<string, unknown>) : undefined,
    queue: coerceQueue(raw["queue"]),
    queueOnly: (raw["queueOnly"] as boolean) ?? undefined,
    ttlMs: (raw["ttlMs"] as number) ?? undefined,
    fieldPermissions: (raw["fieldPermissions"] as Record<string, FieldPermission>) ?? undefined,
    publicKey: (raw["publicKey"] as string) ?? undefined,
  }
}

export function parseConfigJson(raw: string): SyncConfig {
  let parsed: Record<string, unknown>
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>
  } catch (e) {
    throw new StartupError(
      `Failed to parse sync config as JSON: ${e instanceof Error ? e.message : String(e)}`,
    )
  }
  const rawNamespaces = parsed["namespaces"] as Record<string, unknown> | undefined
  let namespaces: Record<string, NamespaceConfig> | undefined
  if (rawNamespaces != null) {
    if (typeof rawNamespaces !== "object" || Array.isArray(rawNamespaces)) {
      throw new StartupError(`Invalid sync config: "namespaces" must be an object`)
    }
    try {
      namespaces = Object.fromEntries(
        Object.entries(rawNamespaces).map(([name, ns]) => {
          if (ns == null || typeof ns !== "object" || Array.isArray(ns)) {
            throw new StartupError(
              `Invalid sync config: namespace "${name}" must be an object, got ${ns === null ? "null" : typeof ns}`,
            )
          }
          return [
            name,
            {
              collections: (((ns as Record<string, unknown>)["collections"] as unknown[]) ?? []).map(
                (c) => parseCollection(c as Record<string, unknown>),
              ),
            },
          ]
        }),
      )
    } catch (e) {
      if (e instanceof StartupError) throw e
      throw new StartupError(
        `Failed to parse namespaces: ${e instanceof Error ? e.message : String(e)}`,
      )
    }
  }

  const config: SyncConfig = {
    version: parsed["version"] as 1,
    collections: ((parsed["collections"] as unknown[]) ?? []).map((c) =>
      parseCollection(c as Record<string, unknown>),
    ),
    namespaces,
    rateLimit: parsed["rateLimit"]
      ? (parsed["rateLimit"] as SyncConfig["rateLimit"])
      : undefined,
  }
  const errors = validateConfig(config)
  if (errors.length > 0) {
    throw new StartupError(`Invalid sync config:\n${errors.join("\n")}`)
  }
  return config
}

export async function loadConfig(
  store: ObjectStore,
  configKey: string = DEFAULT_CONFIG_KEY,
): Promise<SyncConfig | null> {
  const raw = await store.getString(configKey)
  if (raw == null) return null
  return parseConfigJson(raw)
}

export async function saveConfig(
  store: ObjectStore,
  config: SyncConfig,
  configKey: string = DEFAULT_CONFIG_KEY,
): Promise<void> {
  const errors = validateConfig(config)
  if (errors.length > 0) {
    throw new StartupError(`Invalid sync config:\n${errors.join("\n")}`)
  }
  await store.put(configKey, JSON.stringify(config, null, 2), { contentType: CONTENT_TYPE_JSON })
}
