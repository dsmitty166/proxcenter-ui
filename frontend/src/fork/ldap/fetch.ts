// src/fork/ldap/fetch.ts
//
// FORK: the LDAP hook. Upstream calls the orchestrator's LDAP endpoints with
// fetch(); the three hooked call sites call forkLdapFetch() instead. When the
// fork's "ldap" feature is on, those three URLs are answered in-process with
// the same JSON the orchestrator sends. Every other URL, and every URL when
// the feature is off, goes to the real fetch untouched.

import { forkFeatureEnabled } from "../config"

import { handleAuthenticate, handleLookup, handleTest } from "./handlers"

const LDAP_PATH = /\/api\/v1\/auth\/ldap\/(authenticate|test|lookup)\/?$/

function urlOf(input: string | URL | Request): string {
  if (typeof input === "string") return input
  if (input instanceof URL) return input.href
  return input.url
}

/** Which in-process LDAP endpoint this URL names, or null. */
export function forkLdapEndpoint(input: string | URL | Request): "authenticate" | "test" | "lookup" | null {
  try {
    const m = LDAP_PATH.exec(new URL(urlOf(input), "http://localhost").pathname)
    return (m?.[1] as "authenticate" | "test" | "lookup") ?? null
  } catch {
    return null
  }
}

export async function forkLdapFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const endpoint = forkFeatureEnabled("ldap") ? forkLdapEndpoint(input) : null
  if (!endpoint) return fetch(input, init)

  let body: any = {}
  try {
    body = typeof init?.body === "string" ? JSON.parse(init.body) : {}
  } catch {
    return Response.json({ success: false, error: "invalid request body" }, { status: 400 })
  }

  try {
    if (endpoint === "authenticate") return Response.json(await handleAuthenticate(body))
    if (endpoint === "test") return Response.json(await handleTest(body))
    return Response.json(await handleLookup(body))
  } catch (e: any) {
    // Same shape as an orchestrator failure: upstream reports it as an error,
    // never as invalid credentials.
    console.error(`[fork] in-process LDAP ${endpoint} failed:`, e?.message || e)
    return Response.json({ success: false, error: e?.message || "LDAP error" }, { status: 500 })
  }
}
