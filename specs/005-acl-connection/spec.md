# Spec 005: the acl_connection contract — whose session a statement runs under, and session open/close

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: hugr lab (the duckdb-acl session, at tresor's request)
- **Consumer side**: duckdb-acl/specs/078-acl-connection (producer), tresor (the actor spec: delegation)

## Summary

`contracts/acl_connection.hpp` is the charter's third initial contract. It is produced by duckdb-acl
and consumed by tresor. It exposes two things:

- **Whose session a statement runs under.** `AclConnection` is a per-connection state that acl
  publishes for the duration of each statement it runs under `ACL SESSION`.
- **When sessions open and end.** `AclSessionHooks` is an ObjectCache registry of `SessionObserver`s.
  acl calls them on every session open, handing over the verified token for the duration of the
  call only, and exactly once on every close.

tresor needs both to resolve a secret as the session's user, through a delegation grant, instead of
as the node. Without them the node acts as a confused deputy.

## Problem

- **tresor's delegation needs the user's identity.** tresor's delegation (tresor spec 007) needs
  the identity behind a user's session on an acl node, and once, when the session opens, the
  verified token to exchange for a grant. Neither crosses the image boundary today.
- **Nothing tells tresor when a session ends.** Without a signal it cannot revoke the grant.

## Design

**Magic and version.** The magic is `ACLC` and `CONTRACT_VERSION` is 1 (2 since spec 007, the publisher mark). Both objects are stamped
(R3): `AclConnection`, and `AclSessionHooks`, whose stamp sits after its vtable pointer like
`AuditHooks`'s. The contract is independent of `ACLA` (R5). It shares `Principal`
(`acl_principal.hpp`) with the audit contract, so a field added to `Principal` bumps both.

**`AclSessionView`.** It carries:

- `session_id`, the ops id; never the handle, which is a bearer credential;
- `Principal`;
- `door`;
- `opened_at` and `expires_at`, in unix seconds;
- `correlation_id` and `traceparent`.

**`AclConnection`.** It is a `ClientContextState` under key `acl_connection`, reached with
`Reach(ClientContext &, why)`. Reach calls `GetOrCreate`, which casts by key and never checks the
type, so the stamp is the only guard.

- **Reading.** `Current(view)` returns true and fills the view while a statement runs under a
  session.
- **Writing.** `Publish` and `Withdraw` belong to acl. acl publishes at the statement's QueryBegin and
  withdraws at its QueryEnd, including for a failed or interrupted statement. So a gateway's shared
  connection never shows one principal's session to the next.

**`SessionObserver`.**

- `OnSessionOpen(info, access_token)` runs synchronously, after verification and before the session
  is usable. The token is valid only for the call.
- `OnSessionClose(session_id, reason)` runs exactly once for every opened session and after its
  open, whatever ended it. It is never called under acl's locks. A session that opened before the
  observer registered may be announced here without an open.
- `SessionOpenInfo` carries the view's identity fields plus `token_issuer`, the IdP to exchange the
  token at.

**`AclSessionHooks`.** It is an `ObjectCacheEntry` under `acl_session_hooks`, reached with
`Reach(ObjectCache &, why)`, and never evicted. It offers `AddObserver`, `RemoveObserver`, and
`Observers()`, which returns a copy.

**Not an audit contract.** R7's audit rule does not apply. A stricter one does: the token crosses
only by reference, during the open, and the handle never crosses. R8's queue does not apply either,
because a token reference cannot outlive the call. Observers must therefore return promptly and do
the slow work on their own thread. acl measures and counts slow and failing calls, and never fails an
open or a close because of one.

**A mismatch.** Each Reach returns null with `why`. The producer keeps publishing to nobody and
reports it; the consumer does not attach and reports it.

## Compatibility

- The header was checked against `v2.0-cyanoptera` (R9, `check_headers.sh`).
- It ships in v0.4.0 and changes nothing else: `ACLA` stays 2, and `oidc/` is untouched.
- duckdb-acl re-pins to v0.4.0 in its spec 078. acl-otel does not consume this contract and may
  re-pin at leisure.

## Testing

- **Here.** `check_headers.sh` compiles the header on its own.
- **In duckdb-acl (spec 078).** A fake observer sees every open and close, exactly once and in
  order. `AclConnection` shows the session during a session's statement and nothing after it,
  including after an error. The token appears nowhere after the call.
- **In tresor.** The consumer side: the grant, the lookup, fail-closed behaviour, and an e2e against
  the reference server and Keycloak.
