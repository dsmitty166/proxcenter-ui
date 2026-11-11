import { describe, it, expect } from "vitest"

import { attributeValues, buildUserFilter, createClient, entryToUser, identityFilter, isConnectionError } from "./directory"

describe("buildUserFilter", () => {
  it("substitutes every placeholder, escaped", () => {
    expect(buildUserFilter("(|(uid={{username}})(mail={{username}}))", "a*b")).toEqual({
      filter: "(|(uid=a\\2ab)(mail=a\\2ab))",
      placeholder: true,
    })
  })
  it("escapes backslashes and NUL", () => {
    expect(buildUserFilter("(uid={{username}})", "a\\b\u0000").filter).toBe("(uid=a\\5cb\\00)")
  })
  it("wraps a bare template and defaults an empty one", () => {
    expect(buildUserFilter("uid={{username}}", "x").filter).toBe("(uid=x)")
    expect(buildUserFilter("", "x").filter).toBe("(uid=x)")
  })
  it("flags a template without placeholder", () => {
    expect(buildUserFilter("(objectClass=user)", "x")).toEqual({ filter: "(objectClass=user)", placeholder: false })
  })
})

describe("identityFilter", () => {
  it("extracts the identifying clause of a compound filter", () => {
    expect(identityFilter("(&(objectClass=user)(sAMAccountName={{username}}))", "j*")).toBe("(sAMAccountName=j\\2a)")
  })
  it("is null when the filter is that clause alone, or has none", () => {
    expect(identityFilter("(sAMAccountName={{username}})", "j")).toBeNull()
    expect(identityFilter("(objectClass=user)", "j")).toBeNull()
  })
})

describe("entries", () => {
  it("reads attributes case-insensitively, from strings, arrays and buffers", () => {
    const entry = { dn: "CN=x", MAIL: Buffer.from("x@y"), displayname: "X", memberof: ["CN=a", "CN=b"] }
    expect(attributeValues(entry as any, "mail")).toEqual(["x@y"])
    expect(entryToUser(entry as any, { url: "", name_attribute: "displayName" })).toEqual({ dn: "CN=x", email: "x@y", name: "X", groups: ["CN=a", "CN=b"] })
  })
  it("falls back to the e-mail, then the DN, for the display name", () => {
    expect(entryToUser({ dn: "CN=x", mail: "x@y" } as any, { url: "" }).name).toBe("x@y")
    expect(entryToUser({ dn: "CN=x" } as any, { url: "" }).name).toBe("CN=x")
  })
})

describe("createClient", () => {
  // Regression: ldapts goes TLS whenever tlsOptions is set, so passing it for
  // ldap:// sent a TLS handshake to a plain LDAP port.
  it("speaks plain LDAP to ldap:// even with TLS settings filled in", () => {
    const c = createClient({ url: "ldap://dc.corp.example:389", tls_insecure: true, ca_cert: "-----BEGIN CERTIFICATE-----" }) as any
    expect(c.secure).toBe(false)
    expect(c.port).toBe(389)
  })
  it("uses TLS with the CA and verification switch for ldaps://", () => {
    const c = createClient({ url: "LDAPS://dc.corp.example", ca_cert: "PEM" }) as any
    expect(c.secure).toBe(true)
    expect(c.port).toBe(636)
    expect(c.clientOptions.tlsOptions).toEqual({ rejectUnauthorized: true, ca: ["PEM"] })
  })
})

describe("isConnectionError", () => {
  it("recognises socket errors but not LDAP result codes", () => {
    expect(isConnectionError(Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }))).toBe(true)
    expect(isConnectionError(Object.assign(new Error("Invalid credentials"), { code: 49 }))).toBe(false)
  })
})
