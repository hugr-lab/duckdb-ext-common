# Specs

One **lightweight spec per change** — deliberately not full spec-kit: no plan/tasks machinery, just a
short, honest document so decisions are written down and reviewable.

## Process

1. Before (or alongside) a change, create `specs/NNN-slug/spec.md` from `TEMPLATE.md` (`NNN` = next
   zero-padded number, `slug` = short kebab-case).
2. A change that spans repositories is specced on both sides: the part landing here in a spec here,
   the consumer's part in the consumer's repository, each referencing the other.
3. Keep the spec current; set `Status: implemented` when it lands; reference it in the commit/PR.
4. Supersede, don't rewrite: a reversed decision gets a new spec, the old one `superseded by NNN`.

Research and thinking-out-loud live in the local, gitignored `design/` folder.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-charter/spec.md) | the charter — what this repository is, and the rules everything in it follows | accepted |
| [002](002-acl-migration/spec.md) | the duckdb-acl migration — the audit contract and the OIDC core arrive | implemented |
| [003](003-oidc-auth-code/spec.md) | the OIDC core for people — authorization code + PKCE, loopback redirect; the TLS gate fixed | implemented |
| [004](004-oidc-token-exchange/spec.md) | the OIDC core exchanges tokens — RFC 8693 token exchange, Entra On-Behalf-Of | implemented |
| [005](005-acl-connection/spec.md) | the acl_connection contract — whose session a statement runs under, and session open/close | implemented |
| [006](006-exchange-refresh/spec.md) | token exchange that keeps a refresh token, when asked (`with_refresh`) | implemented |
| [007](007-publisher-mark/spec.md) | the publisher mark - a consumer can tell acl is publishing sessions (`ACLC` 2) | implemented |
| [008](008-hooks-tresor-audit/spec.md) | the hooks base and tresor's audit contract (`TRSA` 1) | implemented |
| [009](009-audit-gauges-under-lock/spec.md) | the audit gauges read under their lock (no layout change, ACLA stays 2) | implemented |
