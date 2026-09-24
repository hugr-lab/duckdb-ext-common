# Compatibility

Per tag, the version of every contract it carries, and the duckdb lines its headers were checked
against. Runtime compatibility between two extensions is decided by the contract stamps (charter R3),
not by the tag — two extensions built from different tags interoperate as long as every contract they
share has the same `CONTRACT_VERSION` in both.

| Tag | Contract | Magic | Version | Producer | Checked against |
| --- | --- | --- | --- | --- | --- |
| v0.1.0 | `acl_audit` (`contracts/acl_audit.hpp` + `acl_principal.hpp`) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` (spec 002) |
| v0.2.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` (spec 003: `oidc/` only - the browser flow, the TLS gate fixed) |
| v0.3.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` (spec 004: `oidc/` only - token exchange, On-Behalf-Of) |
| v0.4.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` |
| v0.4.0 | `acl_connection` (`contracts/acl_connection.hpp`, new) | `ACLC` | 1 | duckdb-acl | `v2.0-cyanoptera` (spec 005) |
| v0.5.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` (spec 006: `oidc/` only - token exchange with a refresh token, when asked) |
| v0.5.0 | `acl_connection` (unchanged) | `ACLC` | 1 | duckdb-acl | `v2.0-cyanoptera` |
| v0.6.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` |
| v0.6.0 | `acl_connection` | `ACLC` | 2 | duckdb-acl | `v2.0-cyanoptera` (spec 007: the publisher mark on `AclSessionHooks`) |
| v0.7.0 | `acl_audit` (unchanged) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` |
| v0.7.0 | `acl_connection` (unchanged) | `ACLC` | 2 | duckdb-acl | `v2.0-cyanoptera` |
| v0.7.0 | `tresor_audit` (`contracts/tresor_audit.hpp`, new, on `hooks/ext_hooks.hpp`) | `TRSA` | 1 | tresor | `v2.0-cyanoptera` (spec 008) |
| v0.7.1 | `acl_audit` (spec 009: gauges read under their lock - behaviour, not layout) | `ACLA` | 2 | duckdb-acl | `v2.0-cyanoptera` |
