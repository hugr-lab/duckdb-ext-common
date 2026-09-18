# Spec 002: the duckdb-acl migration - the audit contract and the OIDC core arrive

- **Status**: implemented
- **Date**: 2026-09-18
- **Author**: hugr lab (the duckdb-acl session)

## Summary

The two pieces the charter's "Initial contents" gives the duckdb-acl session: the **audit contract**
(`contracts/acl_audit.hpp` with the `Principal` view it needs, moved as is - the layout does not
change, so `CONTRACT_VERSION` stays 2) and the **OIDC client core** (duckdb-acl spec 060: discovery,
the client-credentials / password / refresh / device flows, the token cache), moved with its test and
its fuzzer into `oidc/` as a module every consumer compiles into itself, under a namespace the
consumer names. duckdb-acl switches to both in its own spec; acl-otel drops its `duckdb-acl`
submodule for this one in its own.

## Problem

acl-otel carried the whole of duckdb-acl (and its nested duckdb, extension-ci-tools and quack) to
read one header. The OIDC core is about to be needed by tresor, and a copy drifts. Both are covered
by the charter; this spec is the move.

## Design

### The contract, moved as is

- `contracts/acl_principal.hpp`: `struct Principal` verbatim from duckdb-acl's `acl_policy.hpp`.
  It is a member of `AuditEvent` by value, so it is part of the contract's layout: a field added
  here is a version bump in `acl_audit.hpp` - an invariant that was true before and is now visible
  where it applies. Includes only `duckdb/common/{case_insensitive_map,string,vector}.hpp`.
- `contracts/acl_audit.hpp`: duckdb-acl's `src/include/acl_audit.hpp` verbatim, one line changed -
  `#include "acl_policy.hpp"` became `#include "acl_principal.hpp"`. Magic `ACLA`, version 2.
  `git diff --no-index` of the two files shows the include and nothing else.
- Narrowing `Principal` to "the view an event needs" (the base's own `ingest_stream`, `arrow_ingest`,
  `session_connection` back into acl) is a bump, and is deferred to the contract's move onto
  `hooks/` (charter, "Initial contents", last row).

### The OIDC core, a module with the consumer's namespace

- `oidc/include/oidc_core.hpp`, `oidc/src/oidc_core.cpp` - duckdb-acl's `acl_oidc.{hpp,cpp}` minus
  the quack-auth discovery (`DoorAuth`, `FetchQuackAuth`, `ParseQuackAuthDocument` are the door's,
  and stay in duckdb-acl over the module's `HttpGet`). Same API otherwise: `HttpGet`,
  `HttpPostForm`, `Discover` / `ParseDiscoveryDocument`, `ClientCredentials`, `PasswordGrant`,
  `RefreshGrant`, `DeviceBegin` / `DevicePoll` / `ParseDeviceAuthorization`, `ParseTokenResponse`,
  `TokenSet`, `Endpoints`, `TokenCache`.
- **The namespace is the consumer's** (the charter's new R13, below): the header refuses to
  compile without `DUCKDB_EXT_COMMON_OIDC_NAMESPACE` and opens
  `namespace duckdb { namespace DUCKDB_EXT_COMMON_OIDC_NAMESPACE { namespace oidc {`. duckdb-acl
  sets `acl`, so its ~25 call sites keep saying `duckdb::acl::oidc::...` unchanged; tresor sets
  `tresor`. Two consumers in one image (a static bundle, or a statically linked one beside a
  co-loaded loadable on Linux's flat namespace) therefore never produce the same symbols - the
  duplicate-symbol / silent-ODR failure duckdb-acl met with its embedded quack.
- **TLS is the consumer's**: `DUCKDB_EXT_COMMON_OIDC_TLS` (was `ACL_OIDC_TLS`) selects
  `CPPHTTPLIB_OPENSSL_SUPPORT` and the `duckdb_httplib_openssl` namespace; the consumer defines it
  where it links OpenSSL.
- **A list of sources, not a library**: `oidc/oidc.cmake` sets `DUCKDB_EXT_COMMON_OIDC_SOURCES` and
  `DUCKDB_EXT_COMMON_OIDC_INCLUDE`; a consumer includes it, appends the sources to its extension's
  and adds the include dir; httplib and yyjson come from its own duckdb tree (charter R10). duckdb's
  `build_static_extension` / `build_loadable_extension` take sources, so the consumer's flags
  (namespace, TLS, visibility) land on the module's TU naturally, and every consumer compiles its
  own copy. The module's TU is compiled with `-fvisibility=hidden` where the compiler has it.
- **Tests and fuzzing**: `oidc/test/test_oidc_core.cpp` (the fake IdP on the bundled httplib) and
  `oidc/fuzz/fuzz_oidc_parse.cpp` with its corpus (discovery, token, device - the quack-auth case
  stays in duckdb-acl). `scripts/test_oidc.sh <duckdb tree>` and `scripts/fuzz_oidc.sh` build them
  against a duckdb source tree with nothing of a built duckdb: the bundled httplib parses status
  lines and query strings through duckdb's `RegexMatch` wrapper over its bundled re2, so the
  scripts compile re2 in from the tree and the test supplies a shim of the wrapper
  (`oidc/test/duckdb_re2_shim.cpp` - duckdb's own reaches into its exception machinery). The module
  itself includes nothing of duckdb's; the wrapper is the bundled headers' reach, not ours.

### The duckdb line

Everything here is checked against the **2.0 line** (`v2.0-cyanoptera`, the branch duckdb-acl and
acl-otel pin) - the owner's decision (2026-09-18): the v1.5.5 line is not a target of this
repository's CI. The two contract headers were also compiled alone against a v1.5.5 tree once, and
do; the module's test is not (v1.5.5's bundled httplib throws duckdb exceptions from its safe
pointers, a chain the shim would have to follow).

### CI

`.github/workflows/ci.yml`: the headers alone against a shallow clone of the 2.0 line; clang-format
11.0.1 over `hooks/`, `contracts/`, `oidc/`; the OIDC test on ubuntu and macOS; the parsers fuzzed
for a minute with clang on ubuntu.

### The tag

`v0.1.0` once this lands: `docs/compatibility.md` gains the row (`acl_audit`, `ACLA`, 2, duckdb-acl),
and duckdb-acl pins it.

## Enforcement & security

- The contract's layout is unchanged: no bump, and acl-otel built from these headers attaches to a
  duckdb-acl built before the move exactly as after (acl-otel's `test_acl_otel_contract`, run
  against both artifacts, is the proof on that side).
- The module carries no secret and keeps none: the token cache is the consumer's memory, as before.
- Nothing crosses an image: the module is compiled into each consumer under its own namespace.

## Testing

- `scripts/check_headers.sh`: both contract headers compile alone against the 2.0 line.
- `scripts/test_oidc.sh`: the OIDC test (discovery with the issuer check, the flows, the device
  poll, the cache margin) passes against the 2.0 line, on macOS locally and in CI on both runners.
- `scripts/fuzz_oidc.sh`: the three parsers under libFuzzer, CI.
- The consumer sides: duckdb-acl's whole gate on the moved code (its spec), acl-otel's contract
  test against the base built before and after (its spec).

## Alternatives considered

- **A fixed namespace `duckdb::ext_common::oidc`** - two consumers in one image collide; the
  consumer-named namespace costs one macro.
- **A CMake library target for the module** - the consumer's flags would not land on it, and
  duckdb's extension helpers take sources anyway.
- **Linking a built duckdb into the module's test** - a 20-minute build for a 2-second test; re2
  from the tree and a 60-line shim is the whole of what the bundled headers reach for.

## Follow-ups

- tresor's additions to `oidc/` (PKCE, `private_key_jwt`, federated assertions) - their spec.
- The contract onto `hooks/` and the narrower `Principal` - at the next natural bump.
