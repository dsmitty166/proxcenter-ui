import { describe, it, expect, vi, beforeEach } from "vitest"

// Constructed lazily: the fake itself imports ldapts (filters, errors).
vi.mock("ldapts", async orig => ({
  ...(await orig<typeof import("ldapts")>()),
  Client: function (opts: any) { return new (globalThis as any).__forkFakeLdapClient(opts) },
}))

import { handleAuthenticate, handleLookup, handleTest, INVALID_CREDENTIALS, normDn } from "./handlers"
import { adConfig, fakeLog, resetFakeLog, GROUP_ADMINS, GROUP_USERS, SVC_DN } from "./testing/fakeDirectory"

beforeEach(() => resetFakeLog())

describe("handleAuthenticate", () => {
  it("binds as the service account, finds the user, binds as the user and returns their groups", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "Admin-Pass-1", config: adConfig() })
    expect(res).toEqual({
      success: true,
      user: {
        dn: "CN=Jane Admin,OU=Users,DC=corp,DC=example",
        email: "Jane.Admin@corp.example",
        name: "Jane Admin",
        avatar: null,
        groups: [GROUP_ADMINS, GROUP_USERS],
      },
    })
    expect(fakeLog.binds.map(b => b.dn)).toEqual([SVC_DN, "CN=Jane Admin,OU=Users,DC=corp,DC=example"])
    expect(fakeLog.unbinds).toBe(1)
  })

  it("answers the exact invalid-credentials text with user_found=true on a wrong password", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "nope", config: adConfig() })
    expect(res).toEqual({ success: false, error: INVALID_CREDENTIALS, reason: "invalid_password", user_found: true })
  })

  it("answers invalid credentials with user_found=false for an unknown user", async () => {
    const res = await handleAuthenticate({ username: "ghost", password: "whatever", config: adConfig() })
    expect(res).toMatchObject({ success: false, error: INVALID_CREDENTIALS, user_found: false, reason: "user_not_found" })
  })

  it("never sends an empty password to the directory (unauthenticated bind)", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "", config: adConfig() })
    expect(res).toMatchObject({ success: false, error: INVALID_CREDENTIALS, reason: "empty_password" })
    expect(fakeLog.binds).toHaveLength(0)
  })

  it("escapes the username so it cannot widen the filter", async () => {
    const res = await handleAuthenticate({ username: "*", password: "x", config: adConfig() })
    expect(res).toMatchObject({ success: false, reason: "user_not_found" })
    expect(fakeLog.searches[0].filter).toBe("(sAMAccountName=\\2a)")

    resetFakeLog()
    await handleAuthenticate({ username: "x)(sAMAccountName=*", password: "x", config: adConfig() })
    expect(fakeLog.searches[0].filter).toBe("(sAMAccountName=x\\29\\28sAMAccountName=\\2a)")
  })

  it("refuses an ambiguous username instead of picking one entry", async () => {
    const res = await handleAuthenticate({ username: "dup", password: "x", config: adConfig() })
    expect(res).toMatchObject({ success: false, reason: "ambiguous_match" })
    expect(res.success === false && res.error).not.toBe(INVALID_CREDENTIALS)
    expect(fakeLog.binds).toHaveLength(1) // service account only
  })

  it("refuses an entry without an e-mail (accounts are keyed by e-mail upstream)", async () => {
    const res = await handleAuthenticate({ username: "nomail", password: "NoMail-Pass-1", config: adConfig() })
    expect(res).toMatchObject({ success: false, reason: "missing_email" })
  })

  it("reports a refused service account as an error, never as invalid credentials", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "Admin-Pass-1", config: adConfig({ bind_password: "wrong" }) })
    expect(res).toMatchObject({ success: false, reason: "service_bind_failed" })
    expect(res.success === false && res.error).not.toBe(INVALID_CREDENTIALS)
  })

  it("reports an unreachable directory as connect_failed", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "Admin-Pass-1", config: adConfig({ url: "ldap://unreachable:389" }) })
    expect(res).toMatchObject({ success: false, reason: "connect_failed" })
  })

  it("rejects an invalid user filter before connecting", async () => {
    const res = await handleAuthenticate({ username: "jadmin", password: "x", config: adConfig({ user_filter: "(sAMAccountName={{username}}" }) })
    expect(res).toMatchObject({ success: false, reason: "invalid_filter" })
    expect(fakeLog.binds).toHaveLength(0)
  })

  it("honours the other clauses of the user filter", async () => {
    const cfg = adConfig({ user_filter: `(&(sAMAccountName={{username}})(memberOf=${GROUP_ADMINS}))` })
    expect((await handleAuthenticate({ username: "jadmin", password: "Admin-Pass-1", config: cfg })).success).toBe(true)
    expect(await handleAuthenticate({ username: "ooperator", password: "Oper-Pass-1", config: cfg })).toMatchObject({ reason: "user_not_found" })
  })

  it("searches anonymously when no bind DN is set", async () => {
    const res = await handleAuthenticate({ username: "rreader", password: "Read-Pass-1", config: adConfig({ bind_dn: "", bind_password: "" }) })
    expect(res.success).toBe(true)
    expect(fakeLog.binds.map(b => b.dn)).toEqual(["CN=Rita Reader,OU=Users,DC=corp,DC=example"])
  })
})

describe("handleTest", () => {
  it("passes connect, bind, base DN and filter, and says what it did not check", async () => {
    const res = await handleTest(adConfig())
    expect(res.success).toBe(true)
    expect(Object.fromEntries(res.checks.map(c => [c.id, c.status]))).toEqual({
      connect: "passed",
      bind: "passed",
      base_dn: "passed",
      user_filter: "passed",
      user_lookup: "not_checked",
      user_password: "not_checked",
      group_membership: "not_checked",
      role_mapping: "not_checked",
    })
  })

  it("fails the bind check on a wrong service password", async () => {
    const res = await handleTest(adConfig({ bind_password: "wrong" }))
    expect(res.success).toBe(false)
    expect(res.checks.find(c => c.id === "connect")?.status).toBe("passed")
    expect(res.checks.find(c => c.id === "bind")?.status).toBe("failed")
  })

  it("fails the connect check on an unreachable server", async () => {
    const res = await handleTest(adConfig({ url: "ldap://unreachable:389" }))
    expect(res.success).toBe(false)
    expect(res.checks.find(c => c.id === "connect")?.status).toBe("failed")
  })

  it("fails the base DN check on a DN outside the directory", async () => {
    const res = await handleTest(adConfig({ base_dn: "DC=elsewhere,DC=example" }))
    expect(res.success).toBe(false)
    expect(res.checks.find(c => c.id === "base_dn")).toMatchObject({ status: "failed", detail: "the Base DN does not exist" })
  })

  it("warns when the user filter has no placeholder", async () => {
    const res = await handleTest(adConfig({ user_filter: "(objectClass=user)" }))
    expect(res.success).toBe(true)
    expect(res.checks.find(c => c.id === "user_filter")?.status).toBe("warning")
  })
})

describe("normDn", () => {
  it("ignores case and spaces around the separators", () => {
    expect(normDn(" CN=Read Only , OU=Groups,DC=corp ,DC=example ")).toBe("cn=read only,ou=groups,dc=corp,dc=example")
  })
  it("stays linear on long runs of spaces (CodeQL js/polynomial-redos)", () => {
    const hostile = "CN=x" + " ".repeat(200_000) + "y"
    const t = performance.now()
    expect(normDn(hostile)).toBe(hostile.toLowerCase())
    expect(performance.now() - t).toBeLessThan(200)
  })
  it("matches a filter clause written with spaces after the commas", async () => {
    // The diagnostic reports jadmin as a direct member of the clause's group,
    // although the clause spells the DN with spaces and the directory without.
    const cfg = adConfig({ user_filter: "(&(sAMAccountName={{username}})(memberOf=CN=VIRT-Admins, OU=Groups, DC=corp, DC=example))" })
    const res = await handleLookup({ username: "jadmin", config: cfg })
    expect(res.filter_groups?.[0]).toMatchObject({ evaluated: true, direct: true })
  })
})

describe("handleLookup", () => {
  it("finds a user without checking any password", async () => {
    const res = await handleLookup({ username: "jadmin", config: adConfig() })
    expect(res).toMatchObject({ status: "found", match_count: 1, password_checked: false, username_placeholder: true })
    expect(res.user?.groups).toEqual([GROUP_ADMINS, GROUP_USERS])
    expect(fakeLog.binds.map(b => b.dn)).toEqual([SVC_DN])
  })

  it("tells 'excluded by the filter' from 'not in the directory' via the identity clause", async () => {
    const cfg = adConfig({ user_filter: `(&(sAMAccountName={{username}})(memberOf=${GROUP_ADMINS}))` })
    const excluded = await handleLookup({ username: "ooperator", config: cfg })
    expect(excluded.status).toBe("not_found")
    expect(excluded.identity).toMatchObject({ filter: "(sAMAccountName=ooperator)", match_count: 1 })
    expect(excluded.identity?.user?.email).toBe("owen@corp.example")
    expect(excluded.filter_groups).toEqual([{ group: GROUP_ADMINS, recursive: false, evaluated: true, direct: false }])

    const missing = await handleLookup({ username: "ghost", config: cfg })
    expect(missing.status).toBe("not_found")
    expect(missing.identity?.match_count).toBe(0)
  })

  it("reports ambiguous matches", async () => {
    const res = await handleLookup({ username: "dup", config: adConfig() })
    expect(res).toMatchObject({ status: "ambiguous", match_count: 2 })
  })

  it("reports the failing stage", async () => {
    expect(await handleLookup({ username: "jadmin", config: adConfig({ bind_password: "wrong" }) })).toMatchObject({ status: "error", stage: "bind" })
    expect(await handleLookup({ username: "jadmin", config: adConfig({ url: "ldap://unreachable" }) })).toMatchObject({ status: "error", stage: "connect" })
    expect(await handleLookup({ username: "", config: adConfig() })).toMatchObject({ status: "error", stage: "input" })
    expect(await handleLookup({ username: "x", config: adConfig({ user_filter: "(uid={{username}}" }) })).toMatchObject({ status: "invalid_filter" })
  })
})
