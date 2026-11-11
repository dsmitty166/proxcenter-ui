# ProxCenter Community fork

This repository is a fork of [adminsyspro/proxcenter-ui](https://github.com/adminsyspro/proxcenter-ui), the AGPL-3.0 Community Edition of ProxCenter. It adds a few features that upstream reserves for the Enterprise Edition, re-implemented here as open code.

It is built so that **upstream releases merge in cleanly**: the fork's code lives in its own files, and upstream files carry only a handful of one-line hooks, each marked `// FORK:`.

## What the fork adds

| Feature id | What you get | How |
|---|---|---|
| `ldap` | LDAP / Active Directory sign-in, the settings page, its connection test and user-lookup diagnostic | Upstream's LDAP code is all in the open frontend except the directory bind, which it sends to the closed-source Go orchestrator. The fork answers those three orchestrator calls in-process with [`ldapts`](https://github.com/ldapts/ldapts) (`frontend/src/fork/ldap/`). Group allow-lists, group → role mapping, lockout, audit and the UI are upstream's, unchanged. |
| `rbac` | Roles page and role picker; LDAP group → role mapping takes effect | Feature switch only. Also withdraws Community's blanket "every new user is super-admin" grant, since roles are now assigned. |
| `oidc` | OIDC / SSO sign-in and settings | Feature switch only (upstream's OIDC runs entirely in the frontend). |
| `syslog_forwarding` | Audit log forwarding to syslog / SIEM | Feature switch only. |
| `compliance` | Compliance page: hardening checks and ISO 27001 / NIST 800-171 / CMMC framework assessments | Feature switch. The PDF report download stays unavailable: it needs upstream's WeasyPrint service. |

Features are switched on with the `PROXCENTER_FORK_FEATURES` environment variable (comma separated). Unset, the fork behaves exactly like upstream Community. Only the ids above are accepted: everything else Enterprise offers (DRS, alerts and notifications, reports, rolling updates, site recovery, change tracking, CVE scanner, flows, firewall pages, …) needs the closed orchestrator and is ignored if listed.

### The LDAP implementation

- Service-account bind (or anonymous when no bind DN), search under the Base DN with the user filter, then a bind as the user's DN with their password. Groups are read from the group attribute (`memberOf`), direct membership only.
- The username is escaped into the filter (RFC 4515): `*`, `(`, `)`, `\` cannot change the filter.
- An empty password is refused without contacting the directory (an empty simple bind is an *unauthenticated* bind that many directories accept).
- More than one matching entry is refused, never "first one wins". A filter matching a whole subtree costs one entry over the limit, not a full read.
- An entry without the e-mail attribute is refused: upstream keys accounts by e-mail.
- `ldaps://` uses TLS with the system store plus the optional CA certificate from the form; "Ignore TLS certificate errors" turns verification off. `ldap://` is plain LDAP (no StartTLS). Use `ldaps://` in production.

## Running it

```sh
# .env as for upstream Community (install-community.sh writes it), then:
docker compose -f docker-compose.community.yml -f docker-compose.fork.yml up -d
```

`docker-compose.fork.yml` swaps in the fork's image (`ghcr.io/dsmitty166/proxcenter-frontend-fork`, built by `fork-image.yml`) and sets `PROXCENTER_FORK_FEATURES` (default `ldap,rbac,syslog_forwarding,compliance`; add `oidc` if you use it).

## Hooks in upstream files

Every change to an upstream file is listed here and checked by `frontend/src/fork/contract/hooks.test.ts`.

| File | Hook | Why |
|---|---|---|
| `frontend/src/lib/license/features.ts` | `effectiveHasFeature` asks `forkGrants()` first | Every feature gate, UI and API, goes through it |
| `frontend/src/app/api/v1/license/status/route.ts` | Community status gains `fork_features` | The browser learns which features are on |
| `frontend/src/lib/auth/ldap.ts` | `fetch` → `forkLdapFetch` on the authenticate call | Sign-in binds in-process |
| `frontend/src/app/api/v1/auth/ldap/test/route.ts` | same, on the test call | Settings connection test |
| `frontend/src/app/api/v1/auth/ldap/diagnose/route.ts` | same, on the lookup call | Settings user-lookup diagnostic |
| `frontend/src/app/api/v1/compliance/frameworks/route.ts` | skip `requireEnterprise()` when `compliance` is on | That route is gated on the edition, not the feature |
| `frontend/src/lib/auth/communitySuperAdmin.ts` | `isCommunityDeployment` false when `rbac` is on | No blanket super-admin once roles exist |
| `frontend/package.json`, `package-lock.json` | `ldapts` dependency | The LDAP client |

Everything else is new files: `frontend/src/fork/**`, `frontend/vitest.fork.config.mts`, `fork/test-ldap-server/`, `docker-compose.fork.yml`, `.github/workflows/fork-*.yml`, this file.

### Rules that keep merges clean

- Never edit an upstream file beyond a hook. New behaviour goes in `frontend/src/fork/`.
- A hook is one or two lines, marked `// FORK:`, listed in the table above and in `HOOKS` in `hooks.test.ts`.
- No reformatting, renaming or lint auto-fixing of upstream files.
- Do not edit upstream's workflows, compose files or install scripts; add `fork-*` files instead.
- `package-lock.json`: change only the entries the fork adds. If npm rewrites unrelated lines (different npm version), keep upstream's lockfile and add the entries alone.

## Merging upstream

`.github/workflows/fork-upstream-sync.yml` runs every Monday (or on demand from the Actions tab):

1. mirrors upstream `main` into the `upstream` branch, so `git diff upstream...main` shows the fork's whole delta;
2. merges the newest upstream release tag (`vX.Y.Z`) into a `sync/upstream-vX.Y.Z` branch and opens a PR;
3. or, if git conflicts, opens an issue naming the files.

Before merging a sync PR, **Fork CI must be green**. A clean git merge does not prove the fork still works: if upstream renames a function or moves a check, a hook can vanish without any conflict. The contract tests catch that:

- `hooks.test.ts`: every hook is still in place, every upstream file that calls the orchestrator's LDAP endpoints goes through the hook, and every hooked file keeps its upstream tests in the fork run;
- `gates.test.ts`, `ldap-flow.test.ts`: the hooks still change the behaviour, through upstream's own code;
- `features.test.ts`: every switchable id is still an upstream feature id.

Resolving a conflict by hand:

```sh
git fetch upstream --tags
git switch -c sync/upstream-vX.Y.Z origin/main
git merge vX.Y.Z                 # resolve; keep upstream's side, then re-apply the FORK hook
# package-lock.json conflict: take upstream's, then add the fork's entries back
cd frontend && npx vitest run -c vitest.fork.config.mts
```

Set the `FORK_SYNC_TOKEN` repository secret (fine-grained PAT with Contents, Pull requests, Issues and Workflows read/write on this repo) so the sync can push merges that touch upstream workflow files and so checks run on its PRs.

## Tests

```sh
cd frontend
npx vitest run -c vitest.fork.config.mts            # fork + contract + upstream tests of hooked files, no database needed

# against a real LDAP server (AD-shaped test directory, test-only):
(cd ../fork/test-ldap-server && npm ci && node server.mjs) &
FORK_LDAP_TEST_URL=ldap://127.0.0.1:10389 npx vitest run -c vitest.fork.config.mts
```

Upstream's full suite (`npx vitest run`, needs Postgres), ESLint and the strict type check run unchanged in upstream's own workflows on every PR.

### Upstream workflows in this fork

Upstream's `docker-publish.yml`, `sonarcloud.yml` and `security-scan.yml` also run here. Their test and lint jobs work; their publish, SonarCloud and orchestrator jobs need upstream's secrets and fail or skip. Disable the ones you do not want from the Actions tab (`gh workflow disable <name>`), which changes no file and so never conflicts.

## License

AGPL-3.0, like upstream. If you let people use a modified version over a network, offer them its source: this public repository does that. Nothing here is taken from the Enterprise Edition; the LDAP code is written against the JSON contract visible in upstream's open frontend.
