// src/fork/ldap/directory.ts
//
// FORK: low-level directory access for the in-process LDAP implementation.
// Everything here is our own code on top of the `ldapts` client; nothing is
// derived from the closed-source orchestrator, only from the JSON contract the
// open frontend expects from it.

import { Client, Filter, FilterParser, type Entry } from "ldapts"

/** The config object upstream sends to the orchestrator LDAP endpoints. */
export interface DirectoryConfig {
  url: string
  bind_dn?: string | null
  bind_password?: string | null
  base_dn?: string | null
  user_filter?: string | null
  email_attribute?: string | null
  name_attribute?: string | null
  tls_insecure?: boolean | null
  ca_cert?: string | null
  group_attribute?: string | null
}

export interface DirectoryUser {
  dn: string
  email: string
  name: string
  groups: string[]
}

export const USERNAME_PLACEHOLDER = "{{username}}"
const DEFAULT_USER_FILTER = "(uid={{username}})"

/** Operation and TCP connect timeouts, ms. Upstream gives the call 15 s overall. */
export const OPERATION_TIMEOUT_MS = 10_000
export const CONNECT_TIMEOUT_MS = 8_000

/** RFC 4515 escaping of a value placed inside a filter. */
export function escapeFilterValue(value: string): string {
  return Filter.escape(value)
}

/**
 * The user filter with the username substituted (escaped, so a username can
 * never change the filter's structure). A template without the placeholder is
 * used as-is, which is what upstream's diagnostic flags as `placeholder_missing`.
 */
export function buildUserFilter(template: string | null | undefined, username: string): { filter: string; placeholder: boolean } {
  let tpl = (template || "").trim() || DEFAULT_USER_FILTER
  if (!tpl.startsWith("(")) tpl = `(${tpl})`
  const placeholder = tpl.includes(USERNAME_PLACEHOLDER)
  const filter = tpl.split(USERNAME_PLACEHOLDER).join(escapeFilterValue(username))
  return { filter, placeholder }
}

/**
 * The single clause that identifies the user, e.g. `(sAMAccountName={{username}})`
 * out of `(&(objectClass=user)(sAMAccountName={{username}})(memberOf=...))`.
 * Used by the diagnostic to tell "no such user" from "the other clauses exclude
 * them". Null when the template has no such clause or is that clause alone.
 */
export function identityFilter(template: string | null | undefined, username: string): string | null {
  const tpl = (template || "").trim() || DEFAULT_USER_FILTER
  const m = /\(([A-Za-z][A-Za-z0-9.;-]*)=\{\{username\}\}\)/.exec(tpl)
  if (!m) return null
  if (m[0] === tpl) return null
  return `(${m[1]}=${escapeFilterValue(username)})`
}

/** Throws when the filter does not parse. */
export function assertFilterSyntax(filter: string): void {
  FilterParser.parseString(filter)
}

/** True for ldaps:// URLs, the only ones that get TLS. */
export function isLdaps(url: string): boolean {
  return /^ldaps:\/\//i.test(url.trim())
}

export function createClient(cfg: DirectoryConfig): Client {
  const ca = (cfg.ca_cert || "").trim()
  return new Client({
    url: cfg.url,
    timeout: OPERATION_TIMEOUT_MS,
    connectTimeout: CONNECT_TIMEOUT_MS,
    // ldaps:// only: ldapts switches to TLS whenever tlsOptions is set, which
    // would speak TLS to a plain ldap:// port 389 and fail. tls_insecure is
    // the form's explicit "ignore TLS certificate errors" switch; otherwise
    // the system store plus the optional CA certificate decide.
    ...(isLdaps(cfg.url)
      ? { tlsOptions: { rejectUnauthorized: !cfg.tls_insecure, ...(ca ? { ca: [ca] } : {}) } }
      : {}),
    // DNs come from the directory itself (memberOf values, bind DNs typed by
    // the administrator): do not reject the odd-but-valid ones client side.
    strictDN: false,
  })
}

/** Bind as the service account, or stay anonymous when no bind DN is set. */
export async function serviceBind(client: Client, cfg: DirectoryConfig): Promise<void> {
  const dn = (cfg.bind_dn || "").trim()
  if (!dn) return
  await client.bind(dn, cfg.bind_password || "")
}

function attributeNames(cfg: DirectoryConfig): string[] {
  return [emailAttribute(cfg), nameAttribute(cfg), groupAttribute(cfg)]
}

export function emailAttribute(cfg: DirectoryConfig): string {
  return (cfg.email_attribute || "").trim() || "mail"
}
export function nameAttribute(cfg: DirectoryConfig): string {
  return (cfg.name_attribute || "").trim() || "cn"
}
export function groupAttribute(cfg: DirectoryConfig): string {
  return (cfg.group_attribute || "").trim() || "memberOf"
}

/**
 * Search the base DN for the filter, returning at most `limit` entries and
 * whether more exist. A user filter should match one entry: the server is
 * asked for limit + 1 at most, so a filter matching half the directory costs
 * nothing and reads as "more" (ambiguous) rather than as a list.
 */
export async function searchUsers(
  client: Client,
  cfg: DirectoryConfig,
  filter: string,
  limit = 10,
): Promise<{ entries: Entry[]; more: boolean }> {
  try {
    const { searchEntries } = await client.search(cfg.base_dn || "", {
      scope: "sub",
      filter,
      attributes: attributeNames(cfg),
      sizeLimit: limit + 1,
    })
    return { entries: searchEntries.slice(0, limit), more: searchEntries.length > limit }
  } catch (e) {
    // The server stops at sizeLimit and says so; the entries it sent are not kept by ldapts.
    if (ldapResultCode(e) === LDAP_SIZE_LIMIT_EXCEEDED) return { entries: [], more: true }
    throw e
  }
}

/** Attribute values as strings, whatever ldapts returned and whatever the attribute name's case. */
export function attributeValues(entry: Entry, name: string): string[] {
  const key = Object.keys(entry).find(k => k.toLowerCase() === name.toLowerCase())
  if (!key || key === "dn") return []
  const raw = entry[key]
  const list = Array.isArray(raw) ? raw : [raw]
  return list
    .map(v => (Buffer.isBuffer(v) ? v.toString("utf8") : String(v)))
    .map(v => v.trim())
    .filter(Boolean)
}

export function entryToUser(entry: Entry, cfg: DirectoryConfig): DirectoryUser {
  const email = attributeValues(entry, emailAttribute(cfg))[0] || ""
  const name = attributeValues(entry, nameAttribute(cfg))[0] || ""
  return {
    dn: entry.dn,
    email,
    name: name || email || entry.dn,
    groups: attributeValues(entry, groupAttribute(cfg)),
  }
}

/** Close the connection, never throwing (the caller already has its answer). */
export async function closeQuietly(client: Client): Promise<void> {
  try {
    await client.unbind()
  } catch {
    // ignore
  }
}

/** Errors raised before the LDAP layer answered (DNS, refused, timeout, TLS). */
export function isConnectionError(err: unknown): boolean {
  const e = err as { code?: unknown; name?: string; message?: string } | null
  if (!e) return false
  if (typeof e.code === "string") return true // Node socket / TLS error codes
  const msg = `${e.name || ""} ${e.message || ""}`
  return /connect|timeout|timed out|socket|ECONN|ENOTFOUND|EHOSTUNREACH|certificate|TLS|self[- ]signed/i.test(msg)
}

/** ldapts result-code errors carry a numeric `code` (49 = invalid credentials). */
export function ldapResultCode(err: unknown): number | null {
  const code = (err as { code?: unknown } | null)?.code
  return typeof code === "number" ? code : null
}

export const LDAP_INVALID_CREDENTIALS = 49
export const LDAP_NO_SUCH_OBJECT = 32
export const LDAP_SIZE_LIMIT_EXCEEDED = 4
