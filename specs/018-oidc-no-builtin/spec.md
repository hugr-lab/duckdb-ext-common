# Spec 018: the OIDC core without its built-in client (wasm)

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor's wasm build (tresor spec 042), which ships to duckdb-wasm; native builds unchanged

## Summary

A wasm build of a consumer compiled the core with its built-in client: the bundled httplib (sockets, even without
TLS), the loopback receiver's thread and, with `DUCKDB_EXT_COMMON_OIDC_TLS`, OpenSSL. In a browser none of these
exist: duckdb-wasm cannot resolve the imports (`socket`, `connect`, `getaddrinfo`, `pthread_create`, `SSL_*`), and a
page's requests go through the browser anyway - the consumer's transport (spec 013, DuckDB's `HTTPUtil`).

## Design

- **`DUCKDB_EXT_COMMON_OIDC_NO_BUILTIN`**: the core compiles no httplib and starts no thread of its own.
  - It is defined by `oidc_core.cpp` itself under `__EMSCRIPTEN__`, so a consumer's wasm build needs nothing; a
    native build may define it (this module's test does).
  - With `DUCKDB_EXT_COMMON_OIDC_TLS` too it is a compile error: TLS is the built-in client's.
- **Every request goes through a transport** (`SetDefaultTransport`, `TransportScope`). Without one a request is
  refused with an error that says so (status 0), never attempted.
- **`LoopbackRedirect::Start`** fails ("no loopback receiver"): a browser login is the page's.
- **Signing** (`private_key_jwt`) is refused as in any build without TLS.
- **No header change**: `oidc/include` and the contracts are as in v0.14.0, so a consumer that builds tresor and
  duckdb-acl into one image (hugr-node, which compares their headers) is unaffected while the two pins differ.

## Testing

- `OIDC_NO_BUILTIN=1 scripts/test_oidc.sh <duckdb tree>`: compiles the core alone and refuses the build if its
  object references `socket`, `connect`, `getaddrinfo`, `bind`, `listen`, `accept`, `send`, `recv`, `poll`,
  `select`, `pthread_create`, `SSL_*` or `EVP_*`; then `oidc/test/test_no_builtin.cpp`: a request and discovery
  refused without a transport, the loopback receiver not started, discovery and a refresh grant through a
  transport, refused again outside its scope.
- CI: the OIDC job gains an ubuntu combination with `no_builtin`.
- The consumer's side (tresor spec 042): its `wasm_eh` / `wasm_mvp` / `wasm_threads` builds, their imports checked,
  and a LOAD in duckdb-wasm.
