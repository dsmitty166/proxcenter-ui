// src/fork/ldap/testing/fakeDirectory.ts
//
// FORK test helper: an in-memory, Active-Directory-shaped stand-in for the
// ldapts Client. Filters are parsed by ldapts itself, so filter syntax and
// escaping are the real thing; only the evaluation is ours (ldapts' own
// matches() cannot handle multi-valued attributes such as memberOf).

import { FilterParser, InvalidCredentialsError, NoSuchObjectError } from "ldapts"

export const BASE_DN = "DC=corp,DC=example"
export const SVC_DN = "CN=svc-proxcenter,OU=Service,DC=corp,DC=example"
export const SVC_PASSWORD = "svc-secret"
export const GROUP_ADMINS = "CN=VIRT-Admins,OU=Groups,DC=corp,DC=example"
export const GROUP_USERS = "CN=VIRT-Users,OU=Groups,DC=corp,DC=example"
export const GROUP_READONLY = "CN=Read Only,OU=Groups,DC=corp,DC=example"

type Attrs = Record<string, string | string[]>
interface FakeEntry { dn: string; password?: string; attrs: Attrs }

export const ENTRIES: FakeEntry[] = [
  { dn: SVC_DN, password: SVC_PASSWORD, attrs: { objectClass: ["top", "user"], sAMAccountName: "svc-proxcenter" } },
  {
    dn: "CN=Jane Admin,OU=Users,DC=corp,DC=example",
    password: "Admin-Pass-1",
    attrs: { objectClass: ["top", "user"], sAMAccountName: "jadmin", mail: "Jane.Admin@corp.example", userPrincipalName: "jadmin@corp.example", displayName: "Jane Admin", memberOf: [GROUP_ADMINS, GROUP_USERS] },
  },
  {
    dn: "CN=Owen Operator,OU=Users,DC=corp,DC=example",
    password: "Oper-Pass-1",
    attrs: { objectClass: ["top", "user"], sAMAccountName: "ooperator", mail: "owen@corp.example", displayName: "Owen Operator", memberOf: [GROUP_USERS] },
  },
  {
    dn: "CN=Rita Reader,OU=Users,DC=corp,DC=example",
    password: "Read-Pass-1",
    attrs: { objectClass: ["top", "user"], sAMAccountName: "rreader", mail: "rita@corp.example", displayName: "Rita Reader", memberOf: [GROUP_READONLY] },
  },
  {
    dn: "CN=No Mail,OU=Users,DC=corp,DC=example",
    password: "NoMail-Pass-1",
    attrs: { objectClass: ["top", "user"], sAMAccountName: "nomail", displayName: "No Mail" },
  },
  {
    // Typical AD account: no mail, a userPrincipalName.
    dn: "CN=Upn Only,OU=Users,DC=corp,DC=example",
    password: "Upn-Pass-1",
    attrs: { objectClass: ["top", "user"], sAMAccountName: "upnonly", userPrincipalName: "upnonly@Corp.Example", displayName: "Upn Only", memberOf: [GROUP_ADMINS] },
  },
  { dn: "CN=Dup One,OU=Users,DC=corp,DC=example", password: "x", attrs: { objectClass: "user", sAMAccountName: "dup", mail: "dup1@corp.example" } },
  { dn: "CN=Dup Two,OU=Users,DC=corp,DC=example", password: "x", attrs: { objectClass: "user", sAMAccountName: "dup", mail: "dup2@corp.example" } },
]

const lower = (s: string) => s.toLowerCase()
const values = (attrs: Attrs, name: string): string[] => {
  const key = Object.keys(attrs).find(k => lower(k) === lower(name))
  if (!key) return []
  const v = attrs[key]
  return Array.isArray(v) ? v : [v]
}

function match(filter: any, attrs: Attrs): boolean {
  switch (filter.constructor.name) {
    case "AndFilter": return filter.filters.every((f: any) => match(f, attrs))
    case "OrFilter": return filter.filters.some((f: any) => match(f, attrs))
    case "NotFilter": return !match(filter.filter, attrs)
    case "PresenceFilter": return values(attrs, filter.attribute).length > 0
    case "EqualityFilter": return values(attrs, filter.attribute).some(v => lower(v) === lower(String(filter.value)))
    // memberOf:1.2.840.113556.1.4.1941: (in chain) evaluated on direct groups only.
    case "ExtensibleFilter": return values(attrs, filter.matchType).some(v => lower(v) === lower(String(filter.value)))
    default: throw new Error(`fake directory: unsupported filter ${filter.constructor.name}`)
  }
}

export interface FakeLog { binds: Array<{ dn: string; password: string }>; searches: Array<{ base: string; filter: string; scope?: string }>; unbinds: number }
export const fakeLog: FakeLog = { binds: [], searches: [], unbinds: 0 }
export function resetFakeLog(): void {
  fakeLog.binds = []
  fakeLog.searches = []
  fakeLog.unbinds = 0
}

/** Drop-in for ldapts' Client. url host "unreachable" simulates a dead server. */
export class FakeClient {
  constructor(public options: { url: string; tlsOptions?: unknown }) {}

  private checkReachable(): void {
    if (/unreachable/.test(this.options.url)) {
      const err: any = new Error(`connect ECONNREFUSED ${this.options.url}`)
      err.code = "ECONNREFUSED"
      throw err
    }
  }

  async bind(dn: string, password?: string): Promise<void> {
    this.checkReachable()
    fakeLog.binds.push({ dn, password: password ?? "" })
    const entry = ENTRIES.find(e => lower(e.dn) === lower(dn))
    if (!entry || !password || entry.password !== password) throw new InvalidCredentialsError("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e")
  }

  async search(base: string, opts: { scope?: string; filter?: string; attributes?: string[] } = {}): Promise<{ searchEntries: any[]; searchReferences: string[] }> {
    this.checkReachable()
    const filter = opts.filter || "(objectClass=*)"
    fakeLog.searches.push({ base, filter, scope: opts.scope })
    if (!lower(base).endsWith(lower(BASE_DN))) throw new NoSuchObjectError("0000208D: NameErr: DSID-03100241, problem 2001 (NO_OBJECT)")
    if (opts.scope === "base") return { searchEntries: [{ dn: base }], searchReferences: [] }
    const parsed = FilterParser.parseString(filter)
    const hits = ENTRIES.filter(e => lower(e.dn).endsWith(lower(base)) && match(parsed, e.attrs))
    const searchEntries = hits.map(e => {
      const out: Record<string, unknown> = { dn: e.dn }
      for (const name of opts.attributes ?? []) {
        const v = values(e.attrs, name)
        if (v.length) out[name] = v.length === 1 ? v[0] : v
      }
      return out
    })
    return { searchEntries, searchReferences: [] }
  }

  async unbind(): Promise<void> {
    fakeLog.unbinds++
  }
}

// Picked up by the lazy ldapts mock in the tests.
;(globalThis as any).__forkFakeLdapClient = FakeClient

/** The config upstream sends to the orchestrator, AD flavoured. */
export function adConfig(overrides: Record<string, unknown> = {}) {
  return {
    url: "ldaps://dc.corp.example:636",
    bind_dn: SVC_DN,
    bind_password: SVC_PASSWORD,
    base_dn: BASE_DN,
    user_filter: "(sAMAccountName={{username}})",
    email_attribute: "mail",
    name_attribute: "displayName",
    tls_insecure: false,
    ca_cert: "",
    group_attribute: "memberOf",
    ...overrides,
  }
}
