// src/fork/ldap/handlers.ts
//
// FORK: in-process answers to the three orchestrator LDAP endpoints upstream
// calls. Each handler takes the exact JSON body upstream sends and returns the
// JSON upstream parses, so upstream's own code keeps doing everything else
// (lockout, allowed groups, role mapping, audit, UI):
//
//   POST /api/v1/auth/ldap/authenticate  <- src/lib/auth/ldap.ts
//   POST /api/v1/auth/ldap/test          <- src/app/api/v1/auth/ldap/test/route.ts
//   POST /api/v1/auth/ldap/lookup        <- src/app/api/v1/auth/ldap/diagnose/route.ts
//
// Never logs or returns a password.

import type { Client } from "ldapts"

import type { LdapLookupResult, FilterGroupCheck, LookupUser } from "@/lib/auth/ldapDiagnostic"

import {
  assertFilterSyntax,
  buildUserFilter,
  closeQuietly,
  createClient,
  entryToUser,
  identityFilter,
  isConnectionError,
  ldapResultCode,
  searchUsers,
  serviceBind,
  LDAP_INVALID_CREDENTIALS,
  LDAP_NO_SUCH_OBJECT,
  type DirectoryConfig,
} from "./directory"

/** Upstream compares the error text to this exact string (src/lib/auth/ldap.ts). */
export const INVALID_CREDENTIALS = "Invalid credentials"

/** Why an entry cannot sign in for lack of an e-mail, for the log and the diagnostic. */
function missingEmailMessage(cfg: DirectoryConfig): string {
  const attr = (cfg.email_attribute || "").trim() || "mail"
  return `the entry has no "${attr}" attribute and no userPrincipalName: ProxCenter identifies accounts by e-mail, so sign-in is refused`
}

function message(err: unknown): string {
  const e = err as { message?: string } | null
  return (e?.message || String(err)).slice(0, 300)
}

// ---------------------------------------------------------------------------
// authenticate

export interface AuthenticateBody {
  username?: unknown
  password?: unknown
  config?: DirectoryConfig
}

export type AuthenticateAnswer =
  | { success: true; user: { dn: string; email: string; name: string; avatar: null; groups: string[] } }
  | { success: false; error: string; reason: string; user_found?: boolean }

export async function handleAuthenticate(body: AuthenticateBody): Promise<AuthenticateAnswer> {
  const username = typeof body.username === "string" ? body.username.trim() : ""
  const password = typeof body.password === "string" ? body.password : ""
  const cfg = body.config

  if (!cfg?.url) return { success: false, error: "LDAP URL is not configured", reason: "not_configured" }
  if (!username) return { success: false, error: INVALID_CREDENTIALS, reason: "empty_username", user_found: false }
  // An empty password is an *unauthenticated* simple bind (RFC 4513 5.1.2),
  // which many directories accept: it must never reach the directory.
  if (!password) return { success: false, error: INVALID_CREDENTIALS, reason: "empty_password" }

  const { filter } = buildUserFilter(cfg.user_filter, username)
  try {
    assertFilterSyntax(filter)
  } catch (e) {
    return { success: false, error: `Invalid user filter: ${message(e)}`, reason: "invalid_filter" }
  }

  const client = createClient(cfg)
  try {
    try {
      await serviceBind(client, cfg)
    } catch (e) {
      if (isConnectionError(e)) return { success: false, error: `Cannot reach the directory: ${message(e)}`, reason: "connect_failed" }
      return { success: false, error: `Service account bind failed: ${message(e)}`, reason: "service_bind_failed" }
    }

    let found
    try {
      found = await searchUsers(client, cfg, filter, 2)
    } catch (e) {
      if (isConnectionError(e)) return { success: false, error: `Cannot reach the directory: ${message(e)}`, reason: "connect_failed" }
      return { success: false, error: `User search failed: ${message(e)}`, reason: "search_failed" }
    }

    if (found.more || found.entries.length > 1) {
      return { success: false, error: "Several directory entries match this username", reason: "ambiguous_match" }
    }
    if (found.entries.length === 0) {
      return { success: false, error: INVALID_CREDENTIALS, reason: "user_not_found", user_found: false }
    }

    const user = entryToUser(found.entries[0], cfg)
    // Upstream keys accounts by e-mail: an entry without one would collide
    // with every other such entry on the empty string.
    if (!user.email) {
      return { success: false, error: missingEmailMessage(cfg), reason: "missing_email" }
    }

    try {
      await client.bind(user.dn, password)
    } catch (e) {
      if (ldapResultCode(e) === LDAP_INVALID_CREDENTIALS) {
        return { success: false, error: INVALID_CREDENTIALS, reason: "invalid_password", user_found: true }
      }
      if (isConnectionError(e)) return { success: false, error: `Cannot reach the directory: ${message(e)}`, reason: "connect_failed" }
      // Account disabled/locked/expired also lands here on AD (code 49 with a
      // data sub-code is handled above; others are reported as errors).
      return { success: false, error: `User bind failed: ${message(e)}`, reason: "user_bind_failed" }
    }

    return { success: true, user: { dn: user.dn, email: user.email, name: user.name, avatar: null, groups: user.groups } }
  } finally {
    await closeQuietly(client)
  }
}

// ---------------------------------------------------------------------------
// test

export type CheckStatus = "passed" | "failed" | "warning" | "skipped" | "not_checked"
export interface TestCheck {
  id: "connect" | "bind" | "base_dn" | "user_filter" | "user_lookup" | "user_password" | "group_membership" | "role_mapping"
  status: CheckStatus
  detail?: string
}

export interface TestAnswer {
  success: boolean
  message: string
  checks: TestCheck[]
}

const NOT_CHECKED_BY_TEST: TestCheck[] = [
  { id: "user_lookup", status: "not_checked" },
  { id: "user_password", status: "not_checked" },
  { id: "group_membership", status: "not_checked" },
  { id: "role_mapping", status: "not_checked" },
]

export async function handleTest(cfg: DirectoryConfig): Promise<TestAnswer> {
  const checks: TestCheck[] = []
  const done = (ok: boolean, msg: string): TestAnswer => {
    for (const id of ["connect", "bind", "base_dn", "user_filter"] as const) {
      if (!checks.some(c => c.id === id)) checks.push({ id, status: "skipped" })
    }
    return { success: ok, message: msg, checks: [...checks, ...NOT_CHECKED_BY_TEST] }
  }

  if (!cfg?.url) return done(false, "LDAP URL is required")

  const client = createClient(cfg)
  try {
    const hasBindDn = !!(cfg.bind_dn || "").trim()
    try {
      // The bind (or, anonymous, the base read below) is what opens the socket.
      await serviceBind(client, cfg)
      if (hasBindDn) {
        checks.push({ id: "connect", status: "passed" })
        checks.push({ id: "bind", status: "passed" })
      }
    } catch (e) {
      if (isConnectionError(e)) {
        checks.push({ id: "connect", status: "failed", detail: message(e) })
        return done(false, `Cannot reach the directory: ${message(e)}`)
      }
      checks.push({ id: "connect", status: "passed" })
      checks.push({ id: "bind", status: "failed", detail: message(e) })
      return done(false, `Service account bind failed: ${message(e)}`)
    }

    const baseDn = (cfg.base_dn || "").trim()
    if (!baseDn) {
      if (!hasBindDn) checks.push({ id: "connect", status: "not_checked" }, { id: "bind", status: "skipped" })
      checks.push({ id: "base_dn", status: "skipped", detail: "no Base DN" })
    } else {
      try {
        await client.search(baseDn, { scope: "base", filter: "(objectClass=*)", attributes: ["dn"] })
        if (!hasBindDn) checks.push({ id: "connect", status: "passed" }, { id: "bind", status: "skipped", detail: "anonymous" })
        checks.push({ id: "base_dn", status: "passed" })
      } catch (e) {
        if (!hasBindDn && isConnectionError(e)) {
          checks.push({ id: "connect", status: "failed", detail: message(e) })
          return done(false, `Cannot reach the directory: ${message(e)}`)
        }
        if (!hasBindDn) checks.push({ id: "connect", status: "passed" }, { id: "bind", status: "skipped", detail: "anonymous" })
        const detail = ldapResultCode(e) === LDAP_NO_SUCH_OBJECT ? "the Base DN does not exist" : message(e)
        checks.push({ id: "base_dn", status: "failed", detail })
        return done(false, `Base DN not readable: ${detail}`)
      }
    }

    const { filter, placeholder } = buildUserFilter(cfg.user_filter, "proxcenter-connection-test")
    try {
      assertFilterSyntax(filter)
      checks.push(placeholder
        ? { id: "user_filter", status: "passed" }
        : { id: "user_filter", status: "warning", detail: "no {{username}} placeholder" })
    } catch (e) {
      checks.push({ id: "user_filter", status: "failed", detail: message(e) })
      return done(false, `Invalid user filter: ${message(e)}`)
    }

    return done(true, "Connection to the directory succeeded")
  } finally {
    await closeQuietly(client)
  }
}

// ---------------------------------------------------------------------------
// lookup (diagnostic, read-only, no password)

export interface LookupBody {
  username?: unknown
  config?: DirectoryConfig
}

function toLookupUser(entry: Parameters<typeof entryToUser>[0], cfg: DirectoryConfig): LookupUser {
  const u = entryToUser(entry, cfg)
  return { dn: u.dn, email: u.email, name: u.name, groups: u.groups }
}

/**
 * DN comparison key: lower-cased, no spaces around the RDN separators.
 * Split and trim rather than /\s*,\s*\/: group DNs come from the directory
 * and the filter, and that regex backtracks quadratically on long runs of spaces.
 */
export const normDn = (dn: string) =>
  dn
    .split(",")
    .map(part => part.trim())
    .join(",")
    .toLowerCase()

/** `(memberOf=...)` clauses of the user filter, checked against the subject's direct groups. */
function filterGroupChecks(template: string, subject: LookupUser | null): FilterGroupCheck[] {
  const out: FilterGroupCheck[] = []
  const re = /\(memberOf(:1\.2\.840\.113556\.1\.4\.1941:)?=([^()]+)\)/gi
  let m: RegExpExecArray | null
  const direct = new Set((subject?.groups ?? []).map(normDn))
  while ((m = re.exec(template))) {
    const group = m[2].trim()
    out.push({
      group,
      recursive: !!m[1],
      evaluated: !!subject,
      direct: !!subject && direct.has(normDn(group)),
    })
  }
  return out
}

export async function handleLookup(body: LookupBody): Promise<LdapLookupResult> {
  const username = typeof body.username === "string" ? body.username.trim() : ""
  const cfg = body.config as DirectoryConfig
  const { filter, placeholder } = buildUserFilter(cfg?.user_filter, username)
  const base: LdapLookupResult = {
    status: "error",
    filter,
    base_dn: cfg?.base_dn || "",
    username_placeholder: placeholder,
    match_count: 0,
    password_checked: false,
  }

  if (!cfg?.url || !username) return { ...base, stage: "input", error: !cfg?.url ? "LDAP URL is required" : "username is required" }

  try {
    assertFilterSyntax(filter)
  } catch (e) {
    return { ...base, status: "invalid_filter", error: message(e) }
  }

  const client: Client = createClient(cfg)
  try {
    try {
      await serviceBind(client, cfg)
    } catch (e) {
      return { ...base, stage: isConnectionError(e) ? "connect" : "bind", error: message(e) }
    }

    let found
    try {
      found = await searchUsers(client, cfg, filter, 10)
    } catch (e) {
      return { ...base, stage: isConnectionError(e) ? "connect" : "search", error: message(e) }
    }

    const matches = found.entries.map(e => e.dn)
    // Over the size limit, the server sends no list: the count shown is "at least limit + 1".
    const result: LdapLookupResult = { ...base, match_count: found.more && matches.length === 0 ? 11 : found.entries.length, more: found.more, matches }

    if (found.more || found.entries.length > 1) return { ...result, status: "ambiguous", filter_groups: filterGroupChecks(cfg.user_filter || "", null) }

    if (found.entries.length === 1) {
      const user = toLookupUser(found.entries[0], cfg)
      const filter_groups = filterGroupChecks(cfg.user_filter || "", user)
      // Sign-in refuses an entry without an e-mail: say so here, rather than
      // "can sign in". The entry, its groups and its role are still reported.
      if (!user.email) return { ...result, status: "error", stage: "search", error: missingEmailMessage(cfg), user, filter_groups, nested_groups: [] }
      return { ...result, status: "found", user, filter_groups, nested_groups: [] }
    }

    // Not found: is the user there at all, and excluded by the other clauses?
    const idFilter = identityFilter(cfg.user_filter, username)
    if (!idFilter) return { ...result, status: "not_found" }
    try {
      const idFound = await searchUsers(client, cfg, idFilter, 10)
      const idUser = idFound.entries.length === 1 ? toLookupUser(idFound.entries[0], cfg) : undefined
      return {
        ...result,
        status: "not_found",
        identity: {
          filter: idFilter,
          match_count: idFound.entries.length,
          more: idFound.more,
          matches: idFound.entries.map(e => e.dn),
          ...(idUser ? { user: idUser } : {}),
        },
        filter_groups: filterGroupChecks(cfg.user_filter || "", idUser ?? null),
      }
    } catch {
      return { ...result, status: "not_found" }
    }
  } finally {
    await closeQuietly(client)
  }
}
