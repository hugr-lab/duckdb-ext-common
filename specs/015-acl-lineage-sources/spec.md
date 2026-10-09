# Spec 015: `acl_lineage_sources` - who names a source in lineage

- **Status**: implemented
- **Date**: 2026-10-09
- **Author**: owner + Claude
- **Producer**: duckdb-acl (its spec 112 §9, the consumer of the answers). **Providers**: hugr_node
  (design: hugr platform 017 §3.7, federation 019 §11), and any extension that owns a source.

## Summary

A new contract: a registry in the ObjectCache through which an extension tells duckdb-acl how a
source it owns is named in lineage. For a dataset of an attached catalog, acl asks the registry, and
the first provider that knows the catalog answers a namespace and a name.
- **A Postgres** gets its OpenLineage name, `postgres://pg.prod:5432` + `sales.public.orders`. A
  Spark job that writes the table directly then meets the node's view of it in one graph.
- **A federated platform** (type `hugr`) gets the remote cluster's virtual name. A physical dataset
  of platform A is then the very virtual dataset of platform B.

New magic `ACLS`, version 1.

## Problem

duckdb-acl spec 107 names a physical dataset by its ATTACH alias, `<ns>/source/<alias>` +
`<schema>.<table>`. Everyone else names the same table by its real address (OpenLineage's naming
spec), so the graphs do not join. acl cannot derive the real address:
- the DSN often lives in a secret that acl does not parse;
- a host behind a proxy is not the host others see;
- a federated source's naming is the remote platform's.

The extension that owns the source knows: hugr_node holds the platform's source registry with the
real addresses, and the remote cluster's namespace for type `hugr`. That extension is another image
(charter R1/R2), so the question needs a contract.

## Design

### `contracts/acl_lineage_sources.hpp`

- **`LineageSourceDataset`** - what acl asks about: the attached catalog's name (its alias), its type
  (`Catalog::GetCatalogType()`: `duckdb`, `hugr`, a scanner's), and the dataset's schema and name
  inside it. An empty schema and name ask about the catalog itself (a `NAMESPACE` event).
- **`LineageSourceName`** - the answer: the OpenLineage namespace and the dataset's name in it.
- **`LineageSourceProvider`** - the interface a provider implements: `Name(query, out)` → true when it
  knows the source.
  - It is called on acl's lineage worker, never on a query's path. It must still be fast and do no
    I/O: it answers from what the provider already holds.
  - An exception is counted and treated as "no answer".
- **`AclLineageSources`** - the registry (ObjectCache key `acl_lineage_sources`, stamped `ACLS` +
  version, `Reach()`):
  - `AddProvider` / `RemoveProvider`;
  - `Name(query, out)` asks the providers in registration order, and the first answer wins.
- **Order of naming in acl** (spec 112 §9):
  1. a provider of this registry;
  2. the identity the operator declared (`acl_lineage_source(alias, identity)` / `ATTACH … LINEAGE`);
  3. the alias form.

### What the contract does not carry

- **No credentials.** An answer is a namespace and a name. A provider must not put userinfo in it,
  and acl refuses an answer that has some.
- **No virtual names.** The cluster's namespace for the virtual catalogs is acl's own setting
  (`acl_lineage_namespace`). This registry names physical sources only.

## Compatibility

- **A new contract**, so no existing stamp moves.
- **Load order.** Either side may create the registry first (`GetOrCreate`), so the order in which
  acl and a provider load does not matter.
- **Mismatch.** A registry stamped with another version is refused: acl names by the declared or
  alias form, and the provider learns it from `Reach`'s `why`.

## Testing

- **This repository:** `check_headers.sh` and clang-format 11.0.1.
- **duckdb-acl spec 112:**
  - a test provider (C++, through this header) renames a source's physical datasets;
  - no provider leaves the declared or alias form;
  - an answer with userinfo is refused;
  - a throwing provider counts as no answer.
- **hugr_node:** its own spec, when it is built.

## Alternatives considered

- **A setting or SQL only (no contract).** The operator would have to restate what hugr_node already
  knows, on every node, and keep it in sync by hand.
- **acl parsing DSNs and secrets.** Wrong for a proxied host, and a secret is not acl's to read for
  this.
- **Putting it into `acl_audit.hpp`.** A different direction, provider to acl rather than acl to
  sinks, and a different lifetime. Its own stamp keeps acl-otel unaffected.
