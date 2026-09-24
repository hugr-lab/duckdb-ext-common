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
  - `contract_magic`, `contract_version` are its first data members (R3);
  - `ReachAs<Derived>(cache, key, why)`: `GetOrCreate` under the key, then the stamp is checked;
    another magic or version gives null and `why`, and nothing past the stamp is read;
  - never evicted (`GetEstimatedCacheMemory` is empty);
  - `AddSink` / `RemoveSink` / `Sinks()` (a copy) / `HasSinks()`;
  - `GetCounters()`, `GetGauges()`.
- **`Sink<Event>`**: `OnEvent(const Event &)`, `Flush()`. Called on the producer's delivery thread,
  never on its decision path.
- **`Delivery<Event>(capacity, sinks, count)`**, owned by the producer, in its own image:
  - `Push` never blocks: a full queue, or one that has stopped, drops the event and counts
    `dropped`;
  - one thread hands each event, in order, to the sinks the `sinks` function returns (the
    registry's, and the producer's own log if it keeps one). An exception from a sink counts
    `sink_failed` and skips that sink for that event (R8);
  - `Stop` (and the destructor) delivers what is queued, joins, and flushes the sinks. Idempotent.
- **`Counters`**: a value per (name, attribute tuple). **`Gauges`**: readers the owner of a state
  registers and removes before the state goes away. **`Metric`**: one row of either. Attributes come
  from bounded sets only (R7).

### `contracts/tresor_audit.hpp` (namespace `duckdb::tresor`)

`TresorAuditHooks` = `Registry<TresorAuditEvent, 'TRSA', 1>` under `"tresor_audit_hooks"`, with
`Reach(cache, why)`. `TresorAuditSink` = `Sink<TresorAuditEvent>`.

`TresorAuditEvent`:

| Field | What |
| --- | --- |
| `ts_us`, `seq` | when it ended; per-instance order |
| `kind` | login, logout, lookup, refresh, write, drop, annotate, grant, revoke, session_grant |
| `outcome` | ok, none (a lookup found nothing here), denied, error |
| `reason_code`, `reason` | on denied/error: no_verb, not_found, actor_not_allowed, mint_refused, unauthenticated, service_unavailable, transport, invalid, no_grant, other; tresor's own text |
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

## Enforcement & security

An event never carries secret material, credentials, tokens, session handles, delegation grant ids,
or statement text (R7). A secret's name, type and service are what a consumer sees. Counters take
only `kind` and `outcome` as attributes.

## Tests

- `scripts/check_headers.sh` compiles both headers on their own against the pinned duckdb.
- `scripts/test_hooks.sh` (in CI): a full queue drops and counts; nothing is accepted after Stop;
  delivery is in order and includes what was queued before Stop; a failing sink is counted while the
  others are still served; Stop flushes; a gauge reads its owner's state and is gone once removed.
- The producer's behaviour (what it emits, when, with which trace context) is tested in tresor
  spec 011; the consumer's in acl-otel.

## Compatibility

A new contract: `TRSA` 1. `ACLA` 2 and `ACLC` 2 are unchanged. Tag `v0.7.0`.
