// FORK: a small Active-Directory-shaped LDAP server for integration tests and
// local demos of the in-process LDAP sign-in. Test-only, never shipped.
//
//   node server.mjs            # listens on 127.0.0.1:10389
//   PORT=1389 node server.mjs
//
// Service account: CN=svc-proxcenter,OU=Service,DC=corp,DC=example / svc-secret
// Users (sAMAccountName / password / groups):
//   jadmin    / Admin-Pass-1  / VIRT-Admins, VIRT-Users
//   ooperator / Oper-Pass-1   / VIRT-Users
//   rreader   / Read-Pass-1   / Read Only
//   nomail    / NoMail-Pass-1 / (neither mail nor userPrincipalName)
//   upnonly   / Upn-Pass-1    / VIRT-Admins (no mail, userPrincipalName only: typical AD)
//   dup       / x             / two entries share this name
import ldap from "ldapjs"

const PORT = Number(process.env.PORT || 10389)
const HOST = process.env.HOST || "127.0.0.1"
const BASE = "DC=corp,DC=example"

const G = {
  admins: "CN=VIRT-Admins,OU=Groups,DC=corp,DC=example",
  users: "CN=VIRT-Users,OU=Groups,DC=corp,DC=example",
  readonly: "CN=Read Only,OU=Groups,DC=corp,DC=example",
}

const entries = [
  { dn: BASE, attrs: { objectClass: ["top", "domain"], dc: "corp" } },
  { dn: "OU=Users,DC=corp,DC=example", attrs: { objectClass: "organizationalUnit", ou: "Users" } },
  { dn: "OU=Groups,DC=corp,DC=example", attrs: { objectClass: "organizationalUnit", ou: "Groups" } },
  { dn: "OU=Service,DC=corp,DC=example", attrs: { objectClass: "organizationalUnit", ou: "Service" } },
  { dn: "CN=svc-proxcenter,OU=Service,DC=corp,DC=example", password: "svc-secret", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "svc-proxcenter" } },
  { dn: "CN=Jane Admin,OU=Users,DC=corp,DC=example", password: "Admin-Pass-1", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "jadmin", mail: "jane.admin@corp.example", userPrincipalName: "jadmin@corp.example", displayName: "Jane Admin", memberOf: [G.admins, G.users] } },
  { dn: "CN=Owen Operator,OU=Users,DC=corp,DC=example", password: "Oper-Pass-1", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "ooperator", mail: "owen.operator@corp.example", displayName: "Owen Operator", memberOf: [G.users] } },
  { dn: "CN=Rita Reader,OU=Users,DC=corp,DC=example", password: "Read-Pass-1", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "rreader", mail: "rita.reader@corp.example", displayName: "Rita Reader", memberOf: [G.readonly] } },
  { dn: "CN=No Mail,OU=Users,DC=corp,DC=example", password: "NoMail-Pass-1", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "nomail", displayName: "No Mail" } },
  { dn: "CN=Upn Only,OU=Users,DC=corp,DC=example", password: "Upn-Pass-1", attrs: { objectClass: ["top", "person", "user"], sAMAccountName: "upnonly", userPrincipalName: "upnonly@Corp.Example", displayName: "Upn Only", memberOf: [G.admins] } },
  { dn: "CN=Dup One,OU=Users,DC=corp,DC=example", password: "x", attrs: { objectClass: "user", sAMAccountName: "dup", mail: "dup1@corp.example" } },
  { dn: "CN=Dup Two,OU=Users,DC=corp,DC=example", password: "x", attrs: { objectClass: "user", sAMAccountName: "dup", mail: "dup2@corp.example" } },
  { dn: G.admins, attrs: { objectClass: "group", cn: "VIRT-Admins" } },
  { dn: G.users, attrs: { objectClass: "group", cn: "VIRT-Users" } },
  { dn: G.readonly, attrs: { objectClass: "group", cn: "Read Only" } },
]

const norm = dn => String(dn).toLowerCase().replace(/\s*,\s*/g, ",").replace(/\s*=\s*/g, "=")
const byDn = new Map(entries.map(e => [norm(e.dn), e]))
const log = (...a) => console.log(new Date().toISOString(), ...a)

const server = ldap.createServer()

server.bind("", (req, res, next) => {
  const dn = req.dn.toString()
  const pw = req.credentials
  if (!dn) { log("bind anonymous"); res.end(); return next() }
  const e = byDn.get(norm(dn))
  if (!e || !e.password || !pw || e.password !== pw) {
    log("bind REFUSED", dn)
    return next(new ldap.InvalidCredentialsError("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e"))
  }
  log("bind ok", dn)
  res.end()
  return next()
})

server.search(BASE, (req, res, next) => {
  const base = norm(req.dn.toString())
  if (!byDn.has(base)) return next(new ldap.NoSuchObjectError(req.dn.toString()))
  // ldapjs reports the scope as a number (0 base, 1 one, 2 sub) or a name, depending on version.
  const scope = { 0: "base", 1: "one", 2: "sub" }[req.scope] ?? req.scope
  let n = 0
  // ldapjs re-filters what we send against the requested names, comparing them lower-cased.
  res.attributes = (res.attributes || []).map(x => x.toLowerCase())
  for (const e of entries) {
    const dn = norm(e.dn)
    const inScope =
      scope === "base" ? dn === base
      : scope === "one" ? dn.endsWith("," + base) && dn.split(",").length === base.split(",").length + 1
      : dn === base || dn.endsWith("," + base)
    if (!inScope) continue
    if (!req.filter.matches(e.attrs, false)) continue // case-insensitive attribute names
    // Attribute selection is case-insensitive, as on AD (ldapjs would compare case-sensitively).
    const wanted = (req.attributes || []).map(x => x.toLowerCase())
    const all = wanted.length === 0 || wanted.includes("*")
    const attributes = Object.fromEntries(Object.entries(e.attrs).filter(([k]) => all || wanted.includes(k.toLowerCase())))
    res.send({ dn: e.dn, attributes }, true)
    n++
  }
  log(`search base="${req.dn.toString()}" scope=${scope} filter=${req.filter.toString()} -> ${n}`)
  res.end()
  return next()
})

server.listen(PORT, HOST, () => log(`test directory listening on ldap://${HOST}:${PORT} (base ${BASE})`))
