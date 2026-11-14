// FORK contract: the gate hooks still do their job through upstream's code.
// A clean upstream merge that moves or drops a hook makes one of these fail.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { callRoute } from "@/__tests__/setup/route-test"

import { FORK_FEATURES_ENV } from "../config"

const requireEnterpriseMock = vi.fn<() => Promise<Response | null>>()
const verifyConnectionOwnershipMock = vi.fn<(id: string) => Promise<Response | null>>()

vi.mock("@/lib/tenant", () => ({
  getSessionPrisma: async () => ({ connection: { findUnique: vi.fn() } }),
  verifyConnectionOwnership: verifyConnectionOwnershipMock,
  getCurrentTenantId: vi.fn(async () => "default"),
  requireProviderTenant: vi.fn(async () => null),
}))
vi.mock("@/lib/rbac", () => ({
  checkPermission: vi.fn(async () => null),
  PERMISSIONS: { ADMIN_COMPLIANCE: "admin.compliance", ADMIN_SETTINGS: "admin.settings" },
}))
vi.mock("@/lib/auth/requireEnterprise", async orig => ({
  ...(await orig<typeof import("@/lib/auth/requireEnterprise")>()),
  requireEnterprise: requireEnterpriseMock,
}))
vi.mock("@/lib/db/prisma", () => ({ prisma: {} }))
// Upstream's IaaS-tenant guard sits between the Enterprise and ownership
// guards; let it pass, as for a provider caller.
vi.mock("@/lib/tenant/iaasGuard", () => ({ denyIaasTenant: vi.fn(async () => null) }))

const ENTERPRISE_ONLY = new Response(JSON.stringify({ error: "Enterprise feature" }), { status: 403 })
const OWNERSHIP_REACHED = new Response(JSON.stringify({ reached: "ownership" }), { status: 418 })

beforeEach(() => {
  vi.clearAllMocks()
  vi.resetModules()
  delete process.env[FORK_FEATURES_ENV]
  requireEnterpriseMock.mockResolvedValue(ENTERPRISE_ONLY.clone())
  verifyConnectionOwnershipMock.mockResolvedValue(OWNERSHIP_REACHED.clone())
  // No orchestrator: every call to it is refused, as on a Community install.
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("fetch failed") }))
})
afterEach(() => {
  delete process.env[FORK_FEATURES_ENV]
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

describe("compliance frameworks route", () => {
  it("stays Enterprise-only when compliance is not switched on", async () => {
    const { GET } = await import("@/app/api/v1/compliance/frameworks/route")
    const res = await callRoute(GET, { searchParams: { connectionId: "c1" } })
    expect(res.status).toBe(403)
  })
  it("skips the Enterprise guard when compliance is switched on, keeping the others", async () => {
    process.env[FORK_FEATURES_ENV] = "compliance"
    const { GET } = await import("@/app/api/v1/compliance/frameworks/route")
    const res = await callRoute(GET, { searchParams: { connectionId: "c1" } })
    expect(res.status).toBe(418) // reached the tenant ownership guard
    expect(requireEnterpriseMock).not.toHaveBeenCalled()
  })
})

describe("server-side feature guard (requireFeature)", () => {
  it("passes for a switched-on feature with no orchestrator, refuses the rest", async () => {
    process.env[FORK_FEATURES_ENV] = "syslog_forwarding"
    const { requireFeature } = await import("@/lib/auth/requireEnterprise")
    expect(await requireFeature("syslog_forwarding")).toBeNull()
    expect((await requireFeature("drs"))?.status).toBe(403)
  })
})

describe("license status route", () => {
  it("tells the browser which features the fork switches on", async () => {
    process.env[FORK_FEATURES_ENV] = "ldap,rbac"
    const { GET } = await import("@/app/api/v1/license/status/route")
    const body = await (await GET()).json()
    expect(body).toMatchObject({ edition: "community", licensed: false, fork_features: ["ldap", "rbac"] })
  })
  it("adds nothing when the fork switches nothing on", async () => {
    const { GET } = await import("@/app/api/v1/license/status/route")
    const body = await (await GET()).json()
    expect(body).not.toHaveProperty("fork_features")
  })
})

describe("Community blanket super-admin grant", () => {
  it("still fires on a plain Community install", async () => {
    vi.stubEnv("ORCHESTRATOR_URL", "")
    const { isCommunityDeployment } = await import("@/lib/auth/communitySuperAdmin")
    expect(isCommunityDeployment({ enterprise: false, edition: "community", licensed: false, expired: false, features: [], options: [] })).toBe(true)
  })
  it("is withdrawn once RBAC is switched on, so roles decide", async () => {
    vi.stubEnv("ORCHESTRATOR_URL", "")
    process.env[FORK_FEATURES_ENV] = "rbac"
    const { isCommunityDeployment } = await import("@/lib/auth/communitySuperAdmin")
    expect(isCommunityDeployment({ enterprise: false, edition: "community", licensed: false, expired: false, features: [], options: [] })).toBe(false)
  })
})
