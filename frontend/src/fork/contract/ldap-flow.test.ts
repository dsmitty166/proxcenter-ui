// FORK contract: upstream's own LDAP code, unchanged apart from the hook,
// produces the right outcome from the fork's in-process answers. If upstream
// changes the JSON it expects from the orchestrator, these fail.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { callRoute, readJson } from "@/__tests__/setup/route-test"

import { FORK_FEATURES_ENV } from "../config"
import { adConfig, GROUP_ADMINS, GROUP_USERS, resetFakeLog } from "../ldap/testing/fakeDirectory"

// Constructed lazily: the fake itself imports ldapts (filters, errors).
vi.mock("ldapts", async orig => ({
  ...(await orig<typeof import("ldapts")>()),
  Client: function (opts: any) { return new (globalThis as any).__forkFakeLdapClient(opts) },
}))

const ldapRow = vi.fn()
vi.mock("@/lib/db/prisma", () => ({
  prisma: {
    ldapConfig: { findUnique: (...a: unknown[]) => ldapRow(...a) },
    user: { findUnique: vi.fn(async () => null) },
    rbacUserRole: { findFirst: vi.fn(async () => null) },
  },
}))
vi.mock("@/lib/crypto/secret", () => ({ decryptSecret: (v: string) => v.replace(/^enc:/, "") }))
vi.mock("@/lib/rbac", () => ({ PERMISSIONS: { ADMIN_SETTINGS: "admin.settings" } }))
vi.mock("@/lib/tenant/providerGuard", () => ({ requireProviderAdmin: vi.fn(async () => null) }))
vi.mock("@/lib/audit", () => ({ audit: vi.fn() }))

function savedRow() {
  const c = adConfig()
  return {
    id: "default",
    enabled: true,
    url: c.url,
    bindDn: c.bind_dn,
    bindPasswordEnc: `enc:${c.bind_password}`,
    baseDn: c.base_dn,
    userFilter: c.user_filter,
    emailAttribute: c.email_attribute,
    nameAttribute: c.name_attribute,
    tlsInsecure: false,
    caCert: null,
    groupAttribute: "memberOf",
    groupRoleMapping: [{ group: GROUP_ADMINS, role: "role_super_admin" }, { group: GROUP_USERS, role: "role_operator" }],
    defaultRole: "role_viewer",
    requireGroup: false,
    allowedGroups: [],
  }
}

let orchestratorFetch: ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()
  resetFakeLog()
  ldapRow.mockImplementation(async (args: any) => (args?.select?.enabled ? { enabled: true } : savedRow()))
  orchestratorFetch = vi.fn(async () => { throw new TypeError("fetch failed") })
  vi.stubGlobal("fetch", orchestratorFetch)
  process.env[FORK_FEATURES_ENV] = "ldap"
})
afterEach(() => {
  delete process.env[FORK_FEATURES_ENV]
  vi.unstubAllGlobals()
})

describe("sign-in: upstream authenticateLdapDetailed via the fork", () => {
  it("returns the directory user and groups, without touching the orchestrator", async () => {
    const { authenticateLdapDetailed, resolveLdapRole, getLdapConfig } = await import("@/lib/auth/ldap")
    const out = await authenticateLdapDetailed("jadmin", "Admin-Pass-1")
    expect(out.failure).toBeNull()
    expect(out.user).toMatchObject({ email: "Jane.Admin@corp.example", groups: [GROUP_ADMINS, GROUP_USERS] })
    expect(resolveLdapRole(out.user!.groups, (await getLdapConfig())!)).toBe("role_super_admin")
    expect(orchestratorFetch).not.toHaveBeenCalled()
  })

  it("maps a wrong password to invalid_password (counts against the account)", async () => {
    const { authenticateLdapDetailed } = await import("@/lib/auth/ldap")
    expect(await authenticateLdapDetailed("jadmin", "bad")).toMatchObject({ user: null, failure: "invalid_password" })
  })

  it("maps an unknown user to user_not_found (counts against the IP only)", async () => {
    const { authenticateLdapDetailed } = await import("@/lib/auth/ldap")
    expect(await authenticateLdapDetailed("ghost", "x")).toMatchObject({ user: null, failure: "user_not_found" })
  })

  it("maps directory trouble to error (no lockout), with the reason for the audit trail", async () => {
    const { authenticateLdapDetailed } = await import("@/lib/auth/ldap")
    expect(await authenticateLdapDetailed("dup", "x")).toMatchObject({ failure: "error", reason: "ambiguous_match" })
  })

  it("goes to the orchestrator exactly as upstream does when the fork LDAP is off", async () => {
    delete process.env[FORK_FEATURES_ENV]
    orchestratorFetch.mockResolvedValue(new Response(JSON.stringify({ success: false, error: "Invalid credentials" })))
    const { authenticateLdapDetailed } = await import("@/lib/auth/ldap")
    await authenticateLdapDetailed("jadmin", "x")
    expect(orchestratorFetch).toHaveBeenCalledTimes(1)
    expect(String(orchestratorFetch.mock.calls[0][0])).toMatch(/\/api\/v1\/auth\/ldap\/authenticate$/)
  })
})

describe("settings: upstream test and diagnose routes via the fork", () => {
  it("connection test answers the checks the UI renders", async () => {
    const { POST } = await import("@/app/api/v1/auth/ldap/test/route")
    const c = adConfig()
    const res = await callRoute(POST as any, { body: { ...c, bind_password: "" } }) // saved password is reused
    const body = await readJson<any>(res)
    expect(body.success).toBe(true)
    expect(body.checks.map((x: any) => x.id)).toEqual(["connect", "bind", "base_dn", "user_filter", "user_lookup", "user_password", "group_membership", "role_mapping"])
    expect(orchestratorFetch).not.toHaveBeenCalled()
  })

  it("user lookup diagnostic evaluates allowed groups and role mapping", async () => {
    const { POST } = await import("@/app/api/v1/auth/ldap/diagnose/route")
    const c = adConfig()
    const res = await callRoute(POST as any, {
      body: {
        ...c,
        test_username: "ooperator",
        require_group: true,
        allowed_groups: [GROUP_ADMINS],
        group_role_mapping: [{ group: GROUP_USERS, role: "role_operator" }],
        default_role: "role_viewer",
      },
    })
    const body = await readJson<any>(res)
    expect(res.status).toBe(200)
    expect(body.data.lookup.status).toBe("found")
    expect(body.data.evaluation.blocker).toBe("not_in_allowed_group")
    expect(body.data.evaluation.role).toMatchObject({ matchedGroup: GROUP_USERS, roleId: "role_operator" })
  })
})
