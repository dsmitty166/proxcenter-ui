// FORK: upstream tests covering the files listed in FORK.md "Hooks". They run
// in the fork's own test run (vitest.fork.config.mts) with the fork code in
// place. Kept in sync by src/fork/contract/hooks.test.ts, which fails if a
// hooked file has no entry here.
export const UPSTREAM_TESTS_OF_HOOKED_FILES = [
  'src/lib/license/features.test.ts',
  'src/app/api/v1/license/status/route.test.ts',
  'src/lib/auth/ldap.test.ts',
  'src/lib/auth/ldap-rbac-sync.test.ts',
  'src/lib/auth/ldapDiagnostic.test.ts',
  'src/app/api/v1/auth/ldap/**/*.test.ts',
  'src/app/api/v1/compliance/frameworks/route.test.ts',
  'src/lib/auth/communitySuperAdmin.test.ts',
]
