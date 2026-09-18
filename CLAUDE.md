# duckdb-ext-common — Development Guidelines

Shared code for the hugr-lab DuckDB extensions: cross-extension **contracts** (`contracts/`), the
header-only **bases** they are built on (`hooks/`), and **duckdb-free modules** compiled into each
consumer (`oidc/`). Consumed as a git submodule; never loaded or linked at runtime.

Read **[specs/001-charter/spec.md](specs/001-charter/spec.md)** first — it is the rule book (R1–R12).
Deeper research lives in the local, gitignored `design/` folder.

## The rules that matter most

- **R1/R2** — a loadable extension is `RTLD_LOCAL` with its own copy of duckdb: nothing crosses an
  image as a function call, and nothing is found by RTTI. Shared objects are reached by string key in
  `ObjectCache` (instance) or `ClientContext::registered_state` (connection), `GetOrCreate` on both
  sides.
- **R3/R4** — every shared object starts with `contract_magic` + `contract_version`; access only via
  `Reach()`; **any layout change bumps `CONTRACT_VERSION`** (comments don't). When in doubt, bump.
- **R6** — a contract belongs to its producer (`acl_*` → duckdb-acl, `tresor_*` → tresor, `mirror_*` →
  mirror). `hooks/` and `oidc/` change only through a spec here. **Parallel sessions stay in the
  directories they own.**
- **R7/R8** — audit contracts never carry secrets, tokens, bearer handles, statement text or
  parameters; bounded metric attributes only; delivery never blocks the decision.
- **R9** — headers compile against **both** duckdb lines in use (v1.5.5 and `v2.0-cyanoptera`); use only
  API stable across them.
- **R10** — `oidc/` and future modules include nothing from `duckdb/` (bundled httplib/yyjson from the
  consumer's tree are fine) and ship their own tests.
- **R13** — a module's namespace is the consumer's (`DUCKDB_EXT_COMMON_OIDC_NAMESPACE`, refused when
  unset) and its TUs are hidden-visibility: two consumers in one image never share a symbol.

## Layout

```text
hooks/        header-only base: stamped registry + Reach, sinks, delivery queue, counters/gauges,
              per-connection state helper                      (owner: through specs here)
contracts/    acl_*.hpp (duckdb-acl), tresor_*.hpp (tresor), mirror_*.hpp (mirror)
oidc/         OIDC client core, duckdb-free: include/, src/, oidc.cmake (a source list), test/, fuzz/
              (owner: through specs here; spec 002 brought it from duckdb-acl)
docs/         compatibility.md — per tag, every contract's version
scripts/      check_headers.sh — every header compiles alone against a duckdb tree;
              test_oidc.sh / fuzz_oidc.sh — the module's test and fuzzer against a duckdb tree
specs/        one lightweight spec per change (see specs/README.md)
design/       LOCAL, gitignored research scratch
```

## Commands

```sh
git clone --depth 1 --branch v2.0-cyanoptera https://github.com/duckdb/duckdb /tmp/duckdb   # or a consumer's duckdb/ submodule
scripts/check_headers.sh /tmp/duckdb                   # every hooks/ and contracts/ header, alone, -fsyntax-only
scripts/test_oidc.sh /tmp/duckdb                       # the OIDC core's test: the module + bundled third party, no built duckdb
CXX=clang++ scripts/fuzz_oidc.sh /tmp/duckdb           # its parsers under libFuzzer (linux)
find hooks contracts oidc \( -name '*.hpp' -o -name '*.cpp' \) | xargs clang-format --dry-run --Werror  # pin 11.0.1
```

The duckdb line is the **2.0 line** (`v2.0-cyanoptera`), the owner's decision of 2026-09-18; CI
checks nothing against v1.5.5.

## Code style

DuckDB's: tabs, ≤120 columns, `idx_t`, `unique_ptr`/`shared_ptr`/`optional_ptr`, no raw owning
pointers, braces always, short comments. Namespaces: `duckdb::<producer>` for contracts
(`duckdb::acl`, `duckdb::tresor`), `duckdb::ext_common` for `hooks/` and modules. Formatter pin:
`clang_format==11.0.1`; `.clang-format` is a real copy of duckdb's (a symlink into a submodule
dangles in a checkout without submodules).

## Process

- One lightweight spec per change in `specs/NNN-slug/spec.md` (from `specs/TEMPLATE.md`), kept current;
  supersede instead of rewriting history. The consumer-side half of a change is specced in the
  consumer's repository.
- A change a consumer's release depends on gets a tag, and `docs/compatibility.md` a row.
- Do not commit `design/`; do not push without being asked.
