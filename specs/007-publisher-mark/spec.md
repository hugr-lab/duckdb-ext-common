# Spec 007: the publisher mark - a consumer can tell acl is publishing sessions

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr lab (the duckdb-acl session, at tresor's request)
- **Consumer side**: duckdb-acl/specs/081-acl-connection-publisher (producer), tresor (the actor spec)

## Summary

`AclSessionHooks` gains a publisher mark: `MarkPublisher(who)`, which acl calls when it loads into
the instance, and `Publisher(who)`, which a consumer reads. `ACLC` goes to version 2.

## Problem

Both sides `GetOrCreate` the registry (spec 005), so a consumer always reaches one. It cannot tell a
node where acl publishes sessions from a node without acl, or with an acl older than the contract:
either way no statement shows a session. A consumer that must act for the session's user (tresor's
`ACT_FOR_SESSIONS`) would then quietly act as the node - the confused deputy spec 005 exists to
prevent.

## Design

- `void MarkPublisher(string who)`: acl's, once at load, e.g. `duckdb-acl <version>`. A later mark
  replaces the text.
- `bool Publisher(string &who) const`: true and `who` filled when a publisher marked the registry.
- The mark is under the registry's own lock; it is never cleared - the instance outlives nothing
  that would unmark it, and an unloaded acl is not a thing duckdb has.
- A layout change of `AclSessionHooks`, so `AclConnectionContract::VERSION` is 2 (R4). A v1 consumer
  reaching a v2 registry is refused by `Reach` with `why`, and the other way round - the same guard
  that already holds.

## Enforcement

The mark says who publishes, nothing more; it carries no identity and no secret (the charter's
stricter rule for this contract holds unchanged). Refusing to run without a publisher is the
consumer's decision.

## Tests

`scripts/check_headers.sh` compiles the header standalone against the pinned duckdb. The producer's
test (duckdb-acl `test/cpp/test_acl_session_hooks.cpp`) checks that the registry is marked after
load, and that a fresh instance without acl reaches an unmarked one.

## Alternatives

- A consumer probing for acl's functions (`acl_sessions()`): by name, across image boundaries, and
  it says acl is loaded, not that it publishes this contract's version. Rejected.
- A bool only: the text costs nothing and is what a consumer's refusal message names.
