// src/fork/features.ts
//
// FORK: the feature-gate hook. Neutral module (no 'use client', no server-only
// imports) because upstream's effectiveHasFeature runs on both sides.
//
// Server: the switched-on features come from the environment (config.ts).
// Browser: they come from the `fork_features` field the license status route
// adds to its Community answer, so the UI and the API always agree.

import { serverForkFeatures, type ForkFeatureId } from "./config"

export interface ForkStatusLike {
  fork_features?: unknown
}

/** True when the fork switches this feature on, whatever the license says. */
export function forkGrants(status: ForkStatusLike | null | undefined, id: string): boolean {
  if (typeof window === "undefined") {
    return (serverForkFeatures() as string[]).includes(id)
  }
  const list = status?.fork_features
  return Array.isArray(list) && list.includes(id)
}

/** Fields the license status route adds to its Community answer. */
export function forkStatusFields(): { fork_features?: ForkFeatureId[] } {
  const features = serverForkFeatures()
  return features.length > 0 ? { fork_features: features } : {}
}
