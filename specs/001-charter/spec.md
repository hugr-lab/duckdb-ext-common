# Spec 001: the charter — what this repository is, and the rules everything in it follows

- **Status**: accepted
- **Date**: 2026-09-18
- **Author**: VGSML

## Summary

`duckdb-ext-common` holds what several hugr-lab DuckDB extensions share but none of them owns:
the **contracts** separately built extensions exchange at runtime, the **header-only bases** those
contracts are built on, and **duckdb-free modules** every consumer compiles into itself. It is
consumed as a git submodule. It is never a library that is loaded or linked at runtime.

## Problem

Three kinds of sharing already exist or are about to, and each one is currently solved badly:

- **Runtime contracts between extensions.** `acl-otel` consumes the audit stream of `duckdb-acl` through
  `acl_audit.hpp`, a header-only contract reached through duckdb's object cache (duckdb-acl spec 069).
  To get that one header, `acl-otel` carries the whole `duckdb-acl` repository as a submodule, and its
  CI checkout (`submodules: recursive`) pulls duckdb-acl's own nested submodules: another duckdb,
  extension-ci-tools, and quack with yet another duckdb. The contract belongs to neither side, but
  lives inside the producer.
- **The pattern behind those contracts.** The stamped object-cache registry, sinks, bounded delivery
  queue and counters/gauges are about to be copied into `tresor` (the secrets-service client) and,
  after that, `mirror` (ingest). Copies drift.
- **Compiled helpers.** The OIDC client core (duckdb-acl spec 060: discovery, client credentials,
  refresh, device flow, token cache) was generalised from mssql-extension's Azure code; `tresor` needs
  it too, plus the browser flow. Three copies of token acquisition is three places to fix a bug.

## Design

### What belongs here

| Kind | Directory | Built how |
| --- | --- | --- |
| Cross-extension **contracts** — the types two separately built extensions exchange at runtime | `contracts/` | header-only, compiled into both sides |
| **Header-only bases** for contracts — the stamped registry, sinks, delivery queue, counters/gauges, the per-connection state helper | `hooks/` | header-only |
| **duckdb-free modules** — code every consumer compiles into itself (the OIDC core) | `oidc/`, later others | sources + a CMake target, compiled per consumer |

What does **not** belong here: any extension's own logic; anything one extension would call as a
function living in another extension's image; any shared object.

### Rules

**R1. Header-only contracts, no cross-image calls.** A loadable extension is `dlopen`ed
`RTLD_LOCAL` and statically embeds duckdb; it can never resolve a symbol of another extension. So a
contract is everything both sides compile from the same header — types, inline functions, virtual
interfaces — and nothing that one side must call in the other's image.

**R2. Reached by name, never by RTTI.** Two images carry two copies of every type, so `dynamic_cast`
and `typeid` across them are meaningless. A shared object is reached by a string key: the instance's
`ObjectCache` (`GetOrCreate<T>(key)`, instance-scoped) or the connection's
`ClientContext::registered_state` (`GetOrCreate<T>(key)` / `Get<T>(key)`, connection-scoped — both
cast by key, not by RTTI). Both sides use `GetOrCreate`, so load order never matters.

**R3. Every contract stamps itself.** The first members of a shared object are
`int32_t contract_magic` (a per-contract four-character tag) and `int32_t contract_version`, written
by whoever creates the object. Access goes only through the contract's `Reach()`, which refuses an
object stamped with another magic or version and says why. A refused object is never dereferenced:
the producer keeps a private one and reports it, the consumer refuses to attach and reports it in its
status.

**R4. Bump on any layout change.** `CONTRACT_VERSION` changes on any change to what a contract header
lays out — fields, enums, virtual interfaces, containers, the types those reference. Comment-only
changes do not bump. When in doubt, bump: a refused attach is a status line, a misread layout is a
crash.

**R5. Contracts are independent.** Each contract has its own magic and version. Bumping one never
forces a consumer of another to rebuild. The repository tag is a build-time pin; runtime
compatibility is decided by the stamps. `docs/compatibility.md` lists, per tag, the version of every
contract it carries.

**R6. Ownership.** A contract belongs to its **producer**: `acl_*` to duckdb-acl, `tresor_*` to tresor,
`mirror_*` to mirror. A consumer asks the producer for a change. The generic bases (`hooks/`) and the
shared modules (`oidc/`) change only through a spec in this repository. Sessions working in
parallel stay inside the directories they own.

**R7. What an audit contract may carry.** Never secret material, credentials, tokens, bearer handles
(session handles, delegation grant ids), statement text or parameters. Metric attributes come only
from bounded sets — never per subject, object or secret name (those belong in events).

**R8. Delivery never blocks the decision.** A producer composes an event and pushes it onto a
bounded queue; a consumer is called on a delivery thread. A slow or failing consumer costs a counted
drop, never latency on a statement or a lookup.

**R9. Every duckdb line a consumer builds on.** Headers compile against each duckdb line in use —
today the **v1.5.5 release** (mssql-ducklake) and the **2.0 line** (`v2.0-cyanoptera` / `main`:
duckdb-acl, acl-otel). CI checks both. A contract uses only duckdb API stable across those lines
(`ObjectCacheEntry`, `ClientContextState`, basic types); when a line drops out of use, it drops out of
CI.

**R10. duckdb-free modules stay duckdb-free.** A shared module may use the third-party headers duckdb
bundles (httplib, yyjson) from the consumer's own duckdb tree, and TLS the consumer's build provides;
it includes nothing from `duckdb/`. It ships its own unit tests.

**R11. Consumed as a submodule.** A consumer adds this repository as a git submodule pinned to a tag
(or a commit on `main` before the first tag) and adds `hooks/` and `contracts/` to its include path;
a module is consumed through its CMake target. Never a vendored copy.

**R12. Tags.** Every change a consumer's release depends on gets a tag (`vMAJOR.MINOR.PATCH`); the
release notes name which contracts changed and their new versions.

**R13. A module compiled into several consumers produces no identical symbols** (added 2026-09-18,
spec 002). A duckdb-free module opens its namespace under one the consumer names
(`DUCKDB_EXT_COMMON_<MODULE>_NAMESPACE`, refused when unset), and its TUs are compiled with hidden
visibility where the compiler has it: a static bundle of two consumers, or a statically linked
consumer beside a co-loaded loadable on a flat namespace, must never find one copy through the
other's symbols.

### Initial contents — who brings what

| Content | Brought by | Notes |
| --- | --- | --- |
| `contracts/acl_audit.hpp` + the `Principal` view it needs | **duckdb-acl session** | moved **as is** — the layout does not change, so **no version bump**; duckdb-acl includes it from the submodule; acl-otel swaps its `duckdb-acl` submodule for this repository |
| `oidc/` — the OIDC core of duckdb-acl spec 060, with its tests | **duckdb-acl session** | duckdb-acl switches to the module |
| `hooks/` — the generic base (registry + stamp + `Reach`, sinks, queue, counters/gauges, per-connection state helper) | **tresor session** | tresor is its first consumer, so tresor designs it |
| `contracts/tresor_audit.hpp` | **tresor session** | on top of `hooks/` |
| `oidc/` additions — authorization code + PKCE with a loopback redirect, `private_key_jwt`, federated assertions (+ the Azure sources from mssql-extension) | **tresor session** | through a spec here, after the module has landed |
| `contracts/acl_connection.hpp` — the per-connection state acl publishes (identity, session ops id, trace context, delegation grant) | duckdb-acl, when tresor's delegation needs it | consumed by tresor |
| duckdb-acl's audit contract moved onto `hooks/` | duckdb-acl, at its next natural contract bump | not forced |

Each session writes its own implementation spec — here for what lands here, in its own repository
for its side of the change.

## Testing

- `scripts/check_headers.sh <duckdb dir>`: every header under `hooks/` and `contracts/` compiles on its
  own (`-fsyntax-only`, C++17) against a duckdb source tree. CI runs it against v1.5.5 and
  `v2.0-cyanoptera`.
- clang-format (duckdb's pin, 11.0.1) over everything under `hooks/`, `contracts/`, `oidc/`;
  `.clang-format` is a real copy of duckdb's, checked against the cloned tree.
- Modules bring their own unit tests (the OIDC core: a fake IdP on the bundled httplib server).

## Alternatives considered

- **Keep contracts in the producer repository** (today's state): consumers pay for the producer's
  whole tree and nested submodules, and a consumer that must not depend on the producer (tresor on
  acl) cannot have the contract at all.
- **vcpkg port / FetchContent**: more machinery than a header directory needs; submodules are how
  every hugr-lab extension already pins its dependencies, and community-extensions CI checks them out.
- **duckdb's native logging instead of audit contracts**: one active log storage per instance, and
  logging is user-switchable — fine for diagnostics, not for audit.

## Follow-ups

- The first tag, once the duckdb-acl migration lands.
- `mirror_audit.hpp` when mirror exists.
