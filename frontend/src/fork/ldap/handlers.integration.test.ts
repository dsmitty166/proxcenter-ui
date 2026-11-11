// FORK: the in-process LDAP handlers against a real LDAP server over TCP,
// with the real ldapts client. Runs only when FORK_LDAP_TEST_URL is set:
//
//   (cd fork/test-ldap-server && npm ci && node server.mjs) &
//   FORK_LDAP_TEST_URL=ldap://127.0.0.1:10389 npx vitest run -c vitest.fork.config.mts
//
// fork-ci.yml does exactly that.
import { describe, it, expect } from "vitest"

import { handleAuthenticate, handleLookup, handleTest, INVALID_CREDENTIALS } from "./handlers"

const URL_ = process.env.FORK_LDAP_TEST_URL
const ADMINS = "CN=VIRT-Admins,OU=Groups,DC=corp,DC=example"
const USERS = "CN=VIRT-Users,OU=Groups,DC=corp,DC=example"

const cfg = (o: Record<string, unknown> = {}) => ({
  url: URL_!,
  bind_dn: "CN=svc-proxcenter,OU=Service,DC=corp,DC=example",
  bind_password: "svc-secret",
  base_dn: "DC=corp,DC=example",
  user_filter: "(&(objectClass=user)(sAMAccountName={{username}}))",
  email_attribute: "mail",
  name_attribute: "displayName",
  tls_insecure: false,
  ca_cert: "",
  group_attribute: "memberOf",
  ...o,
})

describe.skipIf(!URL_)("in-process LDAP against a real server", () => {
  it("signs a user in and returns their groups", async () => {
    expect(await handleAuthenticate({ username: "jadmin", password: "Admin-Pass-1", config: cfg() })).toEqual({
      success: true,
      user: { dn: "CN=Jane Admin,OU=Users,DC=corp,DC=example", email: "jane.admin@corp.example", name: "Jane Admin", avatar: null, groups: [ADMINS, USERS] },
    })
  })

  it("refuses a wrong password, an unknown user, an empty password and a wildcard", async () => {
    expect(await handleAuthenticate({ username: "jadmin", password: "nope", config: cfg() })).toMatchObject({ error: INVALID_CREDENTIALS, user_found: true })
    expect(await handleAuthenticate({ username: "ghost", password: "x", config: cfg() })).toMatchObject({ error: INVALID_CREDENTIALS, user_found: false })
    expect(await handleAuthenticate({ username: "jadmin", password: "", config: cfg() })).toMatchObject({ success: false, reason: "empty_password" })
    expect(await handleAuthenticate({ username: "*", password: "x", config: cfg() })).toMatchObject({ success: false, reason: "user_not_found" })
  })

  it("refuses ambiguous and mail-less entries", async () => {
    expect(await handleAuthenticate({ username: "dup", password: "x", config: cfg() })).toMatchObject({ reason: "ambiguous_match" })
    expect(await handleAuthenticate({ username: "nomail", password: "NoMail-Pass-1", config: cfg() })).toMatchObject({ reason: "missing_email" })
  })

  it("signs in an AD account that has no mail through its userPrincipalName", async () => {
    expect(await handleAuthenticate({ username: "upnonly", password: "Upn-Pass-1", config: cfg() })).toMatchObject({
      success: true,
      user: { email: "upnonly@Corp.Example", name: "Upn Only", groups: [ADMINS] },
    })
  })

  it("runs the connection test", async () => {
    const ok = await handleTest(cfg())
    expect(ok.success).toBe(true)
    expect((await handleTest(cfg({ bind_password: "bad" }))).checks.find(c => c.id === "bind")?.status).toBe("failed")
    expect((await handleTest(cfg({ base_dn: "DC=nowhere,DC=example" }))).checks.find(c => c.id === "base_dn")?.status).toBe("failed")
    expect((await handleTest(cfg({ url: "ldap://127.0.0.1:1" }))).checks.find(c => c.id === "connect")?.status).toBe("failed")
  })

  it("runs the user lookup diagnostic", async () => {
    const found = await handleLookup({ username: "ooperator", config: cfg() })
    expect(found).toMatchObject({ status: "found", match_count: 1, user: { email: "owen.operator@corp.example", groups: [USERS] } })
    const excluded = await handleLookup({ username: "ooperator", config: cfg({ user_filter: `(&(sAMAccountName={{username}})(memberOf=${ADMINS}))` }) })
    expect(excluded).toMatchObject({ status: "not_found", identity: { match_count: 1 } })
  })
})
