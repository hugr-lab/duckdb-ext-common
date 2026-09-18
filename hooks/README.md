# hooks/ — the header-only base for cross-extension contracts

The machinery every contract in `contracts/` is built on (charter R1–R4, R8): a registry held in
duckdb's `ObjectCache` and reached by name, stamped with a magic and a contract version and read only
through `Reach()`; sinks; a bounded delivery queue with its thread; counters and gauges; and the
helper for connection-scoped state in `ClientContext::registered_state`.

**Empty until the tresor bootstrap** — tresor is the first consumer, so it designs this base through a
spec here (charter, "Initial contents"). duckdb-acl's audit contract predates it and moves onto it at
its next natural contract bump.

Namespace: `duckdb::ext_common`. Changes only through a spec in this repository.
