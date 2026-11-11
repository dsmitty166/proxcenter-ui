// src/fork/config.ts
//
// FORK: which Enterprise-gated features this fork switches on for a Community
// deployment. Read from the PROXCENTER_FORK_FEATURES environment variable, a
// comma separated list, e.g. "ldap,rbac,syslog_forwarding,compliance".
//
// Only features whose code runs entirely inside this frontend are accepted (see
// FORK.md). Anything else is ignored with a warning: switching on a feature
// that needs the closed-source orchestrator would only show broken pages.
//
// Unset or empty means the fork behaves exactly like upstream Community.

export const FORK_FEATURES_ENV = "PROXCENTER_FORK_FEATURES"

export const SUPPORTED_FORK_FEATURES = [
  "ldap",
  "rbac",
  "oidc",
  "syslog_forwarding",
  "compliance",
] as const

export type ForkFeatureId = (typeof SUPPORTED_FORK_FEATURES)[number]

const supported = new Set<string>(SUPPORTED_FORK_FEATURES)
const warned = new Set<string>()

/** Parse the env value into the supported feature ids it names, deduplicated. */
export function parseForkFeatures(raw: string | undefined | null): ForkFeatureId[] {
  if (!raw) return []
  const out: ForkFeatureId[] = []
  for (const part of raw.split(/[\s,]+/)) {
    const id = part.trim().toLowerCase()
    if (!id) continue
    if (!supported.has(id)) {
      if (!warned.has(id)) {
        warned.add(id)
        console.warn(`[fork] ${FORK_FEATURES_ENV}: "${id}" is not supported by this fork and is ignored`)
      }
      continue
    }
    if (!out.includes(id as ForkFeatureId)) out.push(id as ForkFeatureId)
  }
  return out
}

/**
 * The fork features switched on for this server process. Always empty in the
 * browser: the browser learns them from the license status payload instead
 * (see forkStatusFields). Read at call time so tests and restarts see changes.
 */
export function serverForkFeatures(): ForkFeatureId[] {
  if (typeof window !== "undefined") return []
  if (typeof process === "undefined" || !process.env) return []
  return parseForkFeatures(process.env[FORK_FEATURES_ENV])
}

/** Server-side: is this fork feature switched on? */
export function forkFeatureEnabled(id: ForkFeatureId | string): boolean {
  return (serverForkFeatures() as string[]).includes(id)
}
