export function deepMerge(
  local: Record<string, unknown>,
  remote: Record<string, unknown>
): Record<string, unknown> {
  const merged = { ...local }
  for (const key of Object.keys(remote)) {
    const remoteVal = remote[key]
    const localVal = merged[key]
    if (
      remoteVal !== null &&
      typeof remoteVal === "object" &&
      !Array.isArray(remoteVal) &&
      localVal !== null &&
      typeof localVal === "object" &&
      !Array.isArray(localVal)
    ) {
      merged[key] = deepMerge(
        localVal as Record<string, unknown>,
        remoteVal as Record<string, unknown>
      )
    } else {
      merged[key] = remoteVal
    }
  }
  return merged
}
