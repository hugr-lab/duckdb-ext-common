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

## Layout

```text
hooks/        header-only base: stamped registry + Reach, sinks, delivery queue, counters/gauges,
              per-connection state helper                      (owner: through specs here)
contracts/    acl_*.hpp (duckdb-acl), tresor_*.hpp (tresor), mirror_*.hpp (mirror)
oidc/         OIDC client core, duckdb-free, sources + CMake target + tests (owner: through specs here)
docs/         compatibility.md — per tag, every contract's version
scripts/      check_headers.sh — every header compiles alone against a duckdb tree
specs/        one lightweight spec per change (see specs/README.md)
design/       LOCAL, gitignored research scratch
```

## Commands

```sh
git clone --depth 1 --branch v1.5.5 https://github.com/duckdb/duckdb /tmp/duckdb-1.5.5   # or any local duckdb tree
scripts/check_headers.sh /tmp/duckdb-1.5.5             # every hooks/ and contracts/ header, alone, -fsyntax-only
find hooks contracts oidc \( -name '*.hpp' -o -name '*.cpp' \) | xargs clang-format --dry-run --Werror  # pin 11.0.1
```

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
