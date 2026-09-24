# duckdb-ext-common

Shared code for the hugr-lab DuckDB extensions — what several of them need and none of them owns:

- **`contracts/`** — the types separately built extensions exchange at runtime (an audit stream, the
  per-connection state one extension publishes for another). Header-only, compiled into both sides.
- **`hooks/`** — the header-only base those contracts are built on: a registry in duckdb's object
  cache reached by name and stamped with a contract version, sinks, a bounded delivery queue,
  counters and gauges.
- **`oidc/`** — the OIDC client core (discovery, token flows, token cache), duckdb-free, compiled into
  each consumer.
- **`keychain/`** — one small secret in the operating system's credential store (macOS Keychain,
  Windows Credential Manager, the Linux Secret Service), duckdb-free, compiled into each consumer;
  never a file.

Consumers today and soon: [duckdb-acl](https://github.com/hugr-lab/duckdb-acl),
[acl-otel](https://github.com/hugr-lab/acl-otel), tresor (secrets-service client), mirror (ingest),
[mssql-extension](https://github.com/hugr-lab/mssql-extension).

**Status**: the audit contract and the OIDC core are in ([specs/002](specs/002-acl-migration/spec.md));
`hooks/` and the tresor contract arrive with the tresor bootstrap ([specs/001](specs/001-charter/spec.md),
"Initial contents").

## Why a separate repository

A loadable DuckDB extension is `dlopen`ed `RTLD_LOCAL` and carries its own copy of duckdb, so two
extensions can never call into each other; what they share at runtime is an object reached by name
and read through a header both compiled. That header belongs to neither the producer nor the
consumer — keeping it inside the producer makes every consumer carry the producer's whole tree.

## Using it

```bash
git submodule add https://github.com/hugr-lab/duckdb-ext-common duckdb-ext-common
git -C duckdb-ext-common checkout <tag>
```

```cmake
include_directories(duckdb-ext-common/hooks duckdb-ext-common/contracts)
```

A module (`oidc/`, `keychain/`) is consumed through its `.cmake` file (`oidc/oidc.cmake`) — a list of sources and an include dir the
consumer compiles into itself under a namespace it names; see [oidc/README.md](oidc/README.md).

## The rules, in short

The full list with reasons is [the charter](specs/001-charter/spec.md). The ones a contributor trips
over:

1. Contracts are header-only; nothing crosses an image as a function call.
2. Shared objects are reached by name (`ObjectCache`, `ClientContext::registered_state`), never by RTTI;
   both sides use `GetOrCreate`, so load order never matters.
3. Every shared object starts with a magic and a `CONTRACT_VERSION`; access only through `Reach()`,
   which refuses a mismatch. **Any layout change bumps the version.**
4. A contract belongs to its producer; `hooks/` and `oidc/` change only through a spec here.
5. Audit contracts never carry secrets, tokens, bearer handles, statement text or parameters.
6. Headers compile alone against the duckdb line the consumers build on (the 2.0 line in CI).
7. A module compiled into several consumers produces no identical symbols: the consumer names
   its namespace (R13).

## Compatibility

[docs/compatibility.md](docs/compatibility.md) — per tag, the version of every contract it carries.

## License

MIT — see [LICENSE](LICENSE).
