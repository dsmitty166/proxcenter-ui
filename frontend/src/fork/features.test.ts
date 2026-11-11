import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"

import { parseForkFeatures, FORK_FEATURES_ENV, SUPPORTED_FORK_FEATURES } from "./config"
import { forkGrants, forkStatusFields } from "./features"
import { Features, effectiveHasFeature } from "@/lib/license/features"

const community = { licensed: false, expired: false, edition: "community", features: [], options: [] }

beforeEach(() => {
  delete process.env[FORK_FEATURES_ENV]
})
afterEach(() => {
  delete process.env[FORK_FEATURES_ENV]
  vi.unstubAllGlobals()
})

describe("parseForkFeatures", () => {
  it("accepts commas and spaces, lower-cases and dedups", () => {
    expect(parseForkFeatures(" LDAP, rbac  ldap,,compliance ")).toEqual(["ldap", "rbac", "compliance"])
  })
  it("ignores features that need the closed orchestrator", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    expect(parseForkFeatures("ldap,drs,reports")).toEqual(["ldap"])
    expect(warn).toHaveBeenCalled()
    warn.mockRestore()
  })
  it("is empty when unset", () => {
    expect(parseForkFeatures(undefined)).toEqual([])
    expect(parseForkFeatures("")).toEqual([])
  })
  it("only lists real upstream feature ids", () => {
    const ids = new Set(Object.values(Features) as string[])
    for (const id of SUPPORTED_FORK_FEATURES) expect(ids.has(id), id).toBe(true)
  })
})

describe("effectiveHasFeature with the fork hook (server side)", () => {
  it("behaves exactly like upstream when nothing is switched on", () => {
    expect(effectiveHasFeature(community, Features.LDAP)).toBe(false)
    expect(effectiveHasFeature(null, Features.LDAP)).toBe(false)
    expect(forkStatusFields()).toEqual({})
  })

  it("grants the switched-on features on Community, and only those", () => {
    process.env[FORK_FEATURES_ENV] = "ldap,rbac"
    expect(effectiveHasFeature(community, Features.LDAP)).toBe(true)
    expect(effectiveHasFeature(community, Features.RBAC)).toBe(true)
    expect(effectiveHasFeature(community, Features.OIDC)).toBe(false)
    expect(effectiveHasFeature(community, Features.DRS)).toBe(false)
    expect(forkStatusFields()).toEqual({ fork_features: ["ldap", "rbac"] })
  })

  it("cannot be used to switch on an orchestrator feature", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    process.env[FORK_FEATURES_ENV] = "drs,firewall,reports"
    expect(effectiveHasFeature(community, Features.DRS)).toBe(false)
    expect(effectiveHasFeature(community, Features.FIREWALL)).toBe(false)
  })
})

describe("forkGrants in the browser", () => {
  it("reads the fork_features of the status payload, never the environment", () => {
    process.env[FORK_FEATURES_ENV] = "ldap"
    vi.stubGlobal("window", {})
    expect(forkGrants({}, "ldap")).toBe(false)
    expect(forkGrants(null, "ldap")).toBe(false)
    expect(forkGrants({ fork_features: ["ldap"] }, "ldap")).toBe(true)
    expect(effectiveHasFeature({ ...community, fork_features: ["rbac"] } as any, Features.RBAC)).toBe(true)
    expect(effectiveHasFeature({ ...community, fork_features: ["rbac"] } as any, Features.LDAP)).toBe(false)
  })
})
