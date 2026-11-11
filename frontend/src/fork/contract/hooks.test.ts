// FORK contract: every hook the fork places in an upstream file is still
// there after a merge, and every hooked file keeps its upstream tests in the
// fork test run. Update HOOKS and FORK.md together.
import { describe, it, expect } from "vitest"
import fs from "node:fs"
import path from "node:path"

import { UPSTREAM_TESTS_OF_HOOKED_FILES } from "../testing/upstreamTests"

const SRC = path.resolve(import.meta.dirname, "..", "..")
const read = (rel: string) => fs.readFileSync(path.join(SRC, rel), "utf8")

export const HOOKS: Array<{ file: string; must: RegExp[]; why: string }> = [
  {
    file: "lib/license/features.ts",
    must: [/import \{ forkGrants \} from '@\/fork\/features'/, /export function effectiveHasFeature\([\s\S]*?\): boolean \{\s*if \(forkGrants\(status as any, id\)\) return true/],
    why: "every feature gate (UI and API) consults the fork first",
  },
  {
    file: "app/api/v1/license/status/route.ts",
    must: [/DEFAULT_COMMUNITY_STATUS = \{[\s\S]*?\.\.\.forkStatusFields\(\)/],
    why: "the browser learns which features the fork switches on",
  },
  {
    file: "lib/auth/ldap.ts",
    must: [/await forkLdapFetch\(`\$\{ORCHESTRATOR_URL\}\/api\/v1\/auth\/ldap\/authenticate`/],
    why: "sign-in binds in-process",
  },
  {
    file: "app/api/v1/auth/ldap/test/route.ts",
    must: [/await forkLdapFetch\(`\$\{ORCHESTRATOR_URL\}\/api\/v1\/auth\/ldap\/test`/],
    why: "the settings connection test runs in-process",
  },
  {
    file: "app/api/v1/auth/ldap/diagnose/route.ts",
    must: [/await forkLdapFetch\(`\$\{ORCHESTRATOR_URL\}\/api\/v1\/auth\/ldap\/lookup`/],
    why: "the settings user-lookup diagnostic runs in-process",
  },
  {
    file: "app/api/v1/compliance/frameworks/route.ts",
    must: [/forkGrants\(null, 'compliance'\) \? null : await requireEnterprise\(\)/],
    why: "compliance frameworks are reachable when switched on",
  },
  {
    file: "lib/auth/communitySuperAdmin.ts",
    must: [/export function isCommunityDeployment\(license: ServerLicense\): boolean \{[\s\S]{0,200}if \(forkGrants\(null, "rbac"\)\) return false/],
    why: "no blanket super-admin once roles exist",
  },
]

describe("fork hooks are in place", () => {
  it.each(HOOKS.map(h => [h.file, h] as const))("%s", (_f, hook) => {
    const src = read(hook.file)
    for (const re of hook.must) expect(src, `${hook.file}: ${hook.why}`).toMatch(re)
  })

  it("no upstream LDAP call site still calls the orchestrator with plain fetch", () => {
    const offenders: string[] = []
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name)
        if (e.isDirectory()) { if (e.name !== "node_modules" && e.name !== "fork") walk(p); continue }
        if (!/\.(ts|tsx|js|jsx)$/.test(e.name) || /\.test\./.test(e.name)) continue
        const s = fs.readFileSync(p, "utf8")
        // Orchestrator calls only: the browser's fetch('/api/v1/auth/ldap/...') to our own API is fine.
        if (/[^.\w]fetch\(\s*`\$\{ORCHESTRATOR_URL\}\/api\/v1\/auth\/ldap\//.test(s)) offenders.push(path.relative(SRC, p))
      }
    }
    walk(SRC)
    // A new upstream LDAP endpoint would land here: hook it, or the fork's LDAP breaks silently.
    expect(offenders).toEqual([])
  })

  it("every hooked file keeps its upstream tests in the fork run", () => {
    for (const { file } of HOOKS) {
      const base = file.replace(/\.ts$/, "")
      const covered = UPSTREAM_TESTS_OF_HOOKED_FILES.some(g => {
        const glob = g.replace(/^src\//, "")
        if (glob.startsWith(`${base}.`)) return true // sibling test, e.g. ldap.test.ts
        return glob.includes("*") && file.startsWith(glob.split("*")[0]) // directory glob
      })
      expect(covered, `${file} has no upstream test in src/fork/testing/upstreamTests.ts`).toBe(true)
    }
  })
})
