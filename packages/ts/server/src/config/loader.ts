import type { SyncConfig } from "./schema.js"
import type { AbstractObjectStore } from "../storage/base.js"
import { validateConfig } from "./validate.js"
import { StartupError } from "../errors.js"
import { DEFAULT_CONFIG_KEY } from "../constants.js"

export function parseConfigJson(raw: string): SyncConfig {
  const config = JSON.parse(raw) as SyncConfig
  if (config.version !== 1) {
    throw new StartupError(`Unsupported config version: ${config.version}`)
  }
  const errors = validateConfig(config)
  if (errors.length > 0) {
    throw new StartupError(`Invalid config: ${errors.join("; ")}`)
  }
  return config
}

export async function loadConfig(
  store: AbstractObjectStore,
  configKey = DEFAULT_CONFIG_KEY,
): Promise<SyncConfig | null> {
  const raw = await store.getString(configKey)
  if (!raw) return null
  return parseConfigJson(raw)
}

export async function saveConfig(
  store: AbstractObjectStore,
  config: SyncConfig,
  configKey = DEFAULT_CONFIG_KEY,
): Promise<void> {
  const errors = validateConfig(config)
  if (errors.length > 0) {
    throw new StartupError(`Invalid config: ${errors.join("; ")}`)
  }
  await store.put(configKey, JSON.stringify(config))
}
