# Spec 008: the hooks base and tresor's audit contract

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/011-audit (producer); acl-otel (consumer, specced in duckdb-acl)

## Summary

Two headers, both header-only (R1):

- **`hooks/ext_hooks.hpp`** — the base the charter reserved for tresor to design ("Initial
  contents"): a stamped registry in the `ObjectCache`, sinks, a bounded delivery queue with its
  thread, counters and gauges.
- **`contracts/tresor_audit.hpp`** — tresor's first contract, magic `TRSA`, version 1:
  `TresorAuditEvent` and `TresorAuditHooks`. acl-otel turns the events into OpenTelemetry.

## Problem

What tresor does — logins, secret lookups, refreshes, management calls, and on a duckdb-acl node the
life of each session's delegation grant — is invisible:
- on a person's laptop, nobody collects it; tresor's own log (tresor spec 011) is the place;
- on a node, acl-otel already exports acl's audit over OTLP. tresor's work belongs in the same
  pipeline, **in the trace of the statement that caused it**.

acl's audit contract (`ACLA` 2) has its own registry and delivery code. A second contract should not
copy it; the charter planned a shared base in `hooks/` for exactly this.

## Design

### `hooks/ext_hooks.hpp` (namespace `duckdb::ext_common`)

- **`Registry<Event, MAGIC, VERSION>`**, an `ObjectCacheEntry`:
  - `contract_magic`, `contract_version`, `hooks_version` are its first data members (R3). The
    third is `EXT_HOOKS_VERSION`, this base's own layout version, so a change to the base cannot hide
    behind an unchanged contract version;
  - `ReachAs<Derived>(cache, why)`: `GetOrCreate` under `Derived::ObjectType()`. duckdb's cache
    compares type names before any cast, and then the stamp is checked. Another type, magic or
    version gives null and `why`, and nothing past the stamp is read;
  - never evicted (`GetEstimatedCacheMemory` is empty);
  - `AddSink` / `RemoveSink` / `Sinks()` (a copy) / `HasSinks()`;
  - `GetCounters()`, `GetGauges()`.
- **`Sink<Event>`**: `OnEvent(const Event &)`, `Flush()`. Called on the producer's delivery thread,
  in push order, never on its decision path. The thread holds its own reference: `OnEvent` may
  still run after `RemoveSink` returns, so a sink owns everything it touches.
- **`Delivery<Event>(capacity, sinks, count)`**, owned by the producer, in its own image:
  - `Push` never blocks: a full queue, or one that has stopped, drops the event and counts
    `dropped`;
  - one thread hands each event, in order, to the sinks the `sinks` function returns (the
    registry's). An exception from a sink counts
    `sink_failed` and skips that sink for that event (R8);
  - nothing that fails on the delivery thread leaves it: a throwing or missing `sinks` function, a
    throwing counter;
  - `Stop` (and the destructor) delivers what is queued, joins, and flushes the sinks. Idempotent.
    Called from a sink, on the delivery thread, it does not wait: the thread, which shares the
    queue's state, drains and ends on its own;
  - a producer that numbers its events does so under its own lock around `Push`, so the numbers
    arrive in order.
- **`Counters`**: a value per (name, attribute tuple), keyed by a length-prefixed encoding so no two
  tuples collide.
- **`Gauges`**: one reader per (name, attributes), registered again to replace it, removed by
  (name, attributes). Readers run under the gauges' lock: once `Remove` returns, the reader never
  runs again and the owner may free its state. A reader must be cheap and must not re-enter.
- **`Metric`**: one row of either. Attributes come from bounded sets only (R7).

### `contracts/tresor_audit.hpp` (namespace `duckdb::tresor`)

`TresorAuditHooks` = `Registry<TresorAuditEvent, 'TRSA', 1>` under `"tresor_audit_hooks"`, with
`Reach(cache, why)`. `TresorAuditSink` = `Sink<TresorAuditEvent>`.

`TresorAuditEvent`:

| Field | What |
| --- | --- |
| `ts_us`, `seq` | when it ended; per-instance order |
| `kind` | login, logout, lookup, refresh, write, drop, annotate, grant, revoke, session_grant |
| `outcome` | ok, none (a lookup found nothing here), denied, error |
| `reason_code`, `reason` | on denied/error: no_verb, not_found, actor_not_allowed, mint_refused, unauthenticated, service_unavailable, transport, invalid, no_grant, other; `reason` is composed from tresor's fixed texts and names only, never an exception's text or the service's or IdP's answer |
| `service`, `host`, `login` | the attached catalog, the service it names, the login flow |
| `principal`, `user` | the attachment's login subject; under an acl session, the session's user |
| `acl_session`, `correlation_id`, `traceparent` | on an acl node under a session: acl's ops id and the statement's trace context, as acl publishes them |
| `secret`, `secret_type`, `cached`, `dynamic` | the secret's name and type; served from cache; minted per request |
| `target` | grant / revoke: the role: or group: principal |
| `duration_us` | the service calls it took; -1 when none |
| `detail` | session_grant: obtained / failed / revoked / rejected / expired |

- **No per-session trace.** An event joins the trace of its statement (`traceparent`); a consumer
  makes its span a child of that. A session-wide trace is a later version, if ever.
- **Nobody listening, nothing composed.** A producer checks `HasSinks()` (and its own log's level)
  before it builds an event.
- **Metrics:** `tresor.events` {kind, outcome, cached} counts every event. A lookup served from
  tresor's cache is counted (cached=true) and not emitted, because a scan asks once per file.
  `tresor.audit.dropped` and `tresor.audit.sink_failed` count delivery's losses.

## Enforcement & security

An event never carries secret material, credentials, tokens, session handles, delegation grant ids,
or statement text (R7). A secret's name, type and service are what a consumer sees. `reason` is
tresor's own words, never foreign text that could quote a value. Counters take only `kind`,
`outcome` and `cached` as attributes; no other field is ever a metric attribute.

## Tests

- `scripts/check_headers.sh` compiles both headers on their own against the pinned duckdb.
- `scripts/test_hooks.sh` (in CI), exact counts throughout:
  - a full queue drops and counts; nothing is accepted after Stop;
  - every accepted event is delivered in order, what was queued at Stop included;
  - a failing sink is counted per event while the others are still served; Stop flushes once;
  - Stop from a sink neither joins itself nor terminates; a missing or throwing `sinks` is survived;
  - attribute tuples that print alike are distinct counters;
  - gauges: read, replaced, removed by (name, attributes), a throwing reader left out.
- The producer's behaviour (what it emits, when, with which trace context) is tested in tresor
  spec 011; the consumer's in acl-otel.

## The review's findings (applied)

- **HIGH: a removed gauge's reader could still run.** A snapshot copied the entries and called the
  readers outside the lock (reproduced). Readers now run under the lock. The same flaw in
  `acl_audit.hpp`'s `AuditGauges` is reported to duckdb-acl.
- **HIGH: an exception on the delivery thread, or a self-join, would terminate the process.** The
  thread now catches everything. `Stop` from the delivery thread detaches, and the queue's state is
  shared with the thread, so it outlives the `Delivery`.
- **Ordering.** Delivery is push order; the producer numbers its events under its lock around `Push`.
- **Free text in `reason`.** The contract now forbids it, and tresor composes reasons from its own
  texts.
- **`RemoveSink` is not a barrier:** documented (a sink owns what it touches).
- **`Gauges::Remove` took every gauge of a name:** now by (name, attributes), and registering again
  replaces.
- **The base's layout was not stamped:** `hooks_version` is.
- **Smaller fixes:**
  - the tests assert exact counts;
  - new tests: Stop from a sink, a throwing `sinks`, colliding attribute tuples, gauge replacement,
    a throwing reader;
  - `ReachAs` takes its key from `Derived::ObjectType()`;
  - counter keys are length-prefixed;
  - `Push` counts a drop outside its lock;
  - comments and README fixed.
- **Not taken now:**
  - an inline namespace per version (loadable extensions are built with hidden visibility; a static
    bundle of producer and consumer from different tags is not a supported build);
  - a time bound on draining at `Stop` (a hung sink is the consumer's bug, and a bound would lose
    events silently);
  - `tracestate` (acl publishes none);
  - ReachAs tests in C++ (they need duckdb's library: tresor's sqllogictests reach the registry
    through a test sink).

## Compatibility

A new contract: `TRSA` 1. `ACLA` 2 and `ACLC` 2 are unchanged. Tag `v0.7.0`.
