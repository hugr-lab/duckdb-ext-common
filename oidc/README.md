# oidc/ — the OIDC client core

duckdb-free token acquisition shared by duckdb-acl, tresor and (later) mssql-extension (charter
R10): endpoint discovery (RFC 8414, with the issuer-match check), the client-credentials, password,
refresh-token and device (RFC 8628) flows, the browser flow (authorization code + PKCE with a
loopback redirect, RFC 7636 / RFC 8252 - spec 003; opening the browser is the consumer's `present`
callback), token exchange (RFC 8693) and Entra's On-Behalf-Of for a server acting for a user
(spec 004), the parsers behind them, and a token cache with a refresh
margin. Uses only the httplib and yyjson duckdb bundles, taken from the consumer's own duckdb tree;
TLS comes from the consumer's build. From duckdb-acl spec 060, moved here by spec 002.

## Consuming it

```cmake
include(duckdb-ext-common/oidc/oidc.cmake)
include_directories(${DUCKDB_EXT_COMMON_OIDC_INCLUDE} duckdb/third_party/httplib duckdb/third_party/yyjson/include)
list(APPEND EXTENSION_SOURCES ${DUCKDB_EXT_COMMON_OIDC_SOURCES})
target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_OIDC_NAMESPACE=<ns>)   # your extension's namespace
target_compile_definitions(<target> PRIVATE DUCKDB_EXT_COMMON_OIDC_TLS=1)            # where you link OpenSSL
```

The namespace is yours (charter R13): the header refuses to compile without
`DUCKDB_EXT_COMMON_OIDC_NAMESPACE`, and the names become `duckdb::<ns>::oidc::...` - duckdb-acl
says `acl`, tresor `tresor`. Every TU that includes `oidc_core.hpp` needs the definition, the
standalone tests of your own included.

## Testing it

```sh
scripts/test_oidc.sh <duckdb source tree>       # the fake-IdP test, nothing of a built duckdb
OIDC_TLS=1 scripts/test_oidc.sh <duckdb tree>   # the TLS variant consumers ship (system OpenSSL; OPENSSL_ROOT=...)
CXX=clang++ scripts/fuzz_oidc.sh <duckdb tree>  # the parsers under libFuzzer (linux)
```

Layout: `include/oidc_core.hpp`, `src/oidc_core.cpp`, `oidc.cmake`, `test/` (the test and a shim of
duckdb's `RegexMatch` wrapper the bundled httplib reaches for), `fuzz/` (the target and its corpus).
