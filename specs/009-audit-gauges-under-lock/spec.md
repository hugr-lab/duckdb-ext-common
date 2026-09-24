# Spec 009: the audit gauges read under their lock

- **Status**: implemented
- **Date**: 2026-09-24
- **Found by**: tresor, while porting the same code into `hooks/ext_hooks.hpp` (spec 008), where it is
  already fixed
- **Consumers**: duckdb-acl (the gauges' owners) and acl-otel (which calls `Snapshot`)

## Problem

`AuditGauges::Snapshot()` copied the entries under the lock and called the readers after releasing
it. An owner that calls `Remove()` and then frees its state could therefore have a copied reader of
it run on freed memory. The window is a snapshot already under way when `Remove()` returns, for
example acl-otel's export thread reading `acl.audit.queue_fill` while acl's audit pipeline is
destroyed.

## Design

- The readers run under the registry's lock, so `Remove()` waits for a snapshot that is calling a
  reader it removes. Once `Remove()` returns, the owner may free what that reader touches.
- This is a behaviour change, not a layout change. `AuditHooks::CONTRACT_VERSION` stays 2 (R4), and a
  consumer built from either revision reaches the same registry.
- **The owner's rule, now written on `Snapshot`.** A reader must not call back into the gauges, and
  must not take a lock that is held while `Register()` or `Remove()` is called. acl's readers take only
  their own short locks: the audit queue, the ring, the store, and the stream budget. acl calls
  `Register` at load and serve and `Remove` in the pipeline's destructor, without holding any of those.

## Tests

- duckdb-acl `test/cpp/test_acl_audit_gauges.cpp`: a reader is held inside `Snapshot()`, and
  `Remove()` on another thread must not return until that reader has finished. Without the fix it
  returns at once.
- `scripts/check_headers.sh` passes.
