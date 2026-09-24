# hooks/ — the header-only base for cross-extension contracts

The machinery every contract in `contracts/` is built on (charter R1–R4, R8): a registry held in
duckdb's `ObjectCache` and reached by name, stamped with a magic and a contract version and read only
through `Reach()`; sinks; a bounded delivery queue with its thread; counters and gauges; and the
helper for connection-scoped state in `ClientContext::registered_state`.

`ext_hooks.hpp` (spec 008), designed with tresor, its first producer:

- `Registry<Event, MAGIC, VERSION>`: the stamp as the first members, `ReachAs<Derived>(cache, key,
  why)` (created when absent, refused when stamped otherwise), sinks, `HasSinks()` (a producer
  composes nothing when nobody listens), counters and gauges;
- `Sink<Event>`: `OnEvent`, `Flush`, called on the producer's delivery thread;
- `Delivery<Event>`: the producer's bounded queue and thread. `Push` never blocks; a full queue drops
  and counts. `Stop` delivers what is queued, joins, flushes;
- `Counters` / `Gauges` / `Metric`: bounded attributes only (R7).

The connection-scoped state helper arrives with the first contract that needs it. duckdb-acl's audit
contract predates this base and moves onto it at its next natural contract bump.

`scripts/test_hooks.sh <duckdb>` runs `hooks/test/test_hooks.cpp` (no duckdb build: headers only).

Namespace: `duckdb::ext_common`. Changes only through a spec in this repository.
