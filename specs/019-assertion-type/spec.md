# Spec 019: a client assertion's type - a JWT-SVID as jwt-spiffe

- **Status**: implemented
- **Date**: 2026-10-29
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor spec 046 (a node's SPIFFE login: `ASSERTION_TYPE` on its `tresor` secret); duckdb-acl
  unchanged (it sends no federated assertion)

## Summary

`ClientAuth` gains `assertion_type`, the `client_assertion_type` a caller's federated assertion is sent as. Empty is
RFC 7523's `jwt-bearer`, as every assertion was sent until now, so no caller changes. Keycloak's SPIFFE client
authentication (the identity provider type `spiffe`, a preview feature since 26.4) takes a JWT-SVID only as
`urn:ietf:params:oauth:client-assertion-type:jwt-spiffe` (the IETF draft "OAuth SPIFFE Client Authentication") and
refuses it as `jwt-bearer` with `invalid_client` - tresor's spike checked both against Keycloak 26.8.1.

## Problem

`AddClientAuth` sent `jwt-bearer` for every assertion, the platform's (`ClientAuth::assertion`) and the one it signs
(`private_key_pem`). A consumer could not send a JWT-SVID to Keycloak's SPIFFE authentication: `extra` parameters
never replace the core's own (`emplace`), by design.

## Design

- `ClientAuth::assertion_type` (`std::string`, after `assertion`): the full URN; empty is `jwt-bearer`. The core does
  not list types: an IdP's type is the IdP's, and a consumer names the ones it offers (tresor: `jwt-bearer`,
  `jwt-spiffe`).
- It applies to the caller's `assertion` only. An assertion signed here (`private_key_pem`, private_key_jwt) is
  `jwt-bearer` (RFC 7523 §2.2); another type with a key is refused before anything is signed or sent ("a client
  assertion signed with a private key is jwt-bearer, not …").
- Every grant that authenticates the client takes it: client credentials, token exchange, On-Behalf-Of
  (`AddClientAuth` is theirs).
- Nothing else changes: the assertion is still cut out of an IdP's error and wiped from the request's parameters.

## Compatibility

A source change of the module, no contract: no `CONTRACT_VERSION` moves, `check_headers.sh` is unaffected
(`oidc/` is not a header-only base). `ClientAuth` grows a member: a consumer that aggregate-initializes it
positionally still compiles (the new member is last). Consumers rebuild when they take the tag; until then nothing
changes for them. Checked with the 2.0 line (DuckDB v2.0.0, d54cbbe).

## Testing

`oidc/test/test_oidc_core.cpp`, the fake IdP with a client as Keycloak's SPIFFE authentication (`spiffe-client`:
`jwt-spiffe` only): no type is `jwt-bearer`, which it refuses; `jwt-spiffe` is granted; `jwt-bearer` named explicitly
is `jwt-bearer` (`fed-client`); a key with another type is refused before signing. Plain and `OIDC_TLS=1`.

## Alternatives considered

- **A fixed list of types in the core** (an enum) - a new IdP's type would need a core change; the URN is the IdP's
  word, and the consumer validates what it offers.
- **Letting `extra` replace `client_assertion_type`** - `extra` must never replace the core's own parameters (the
  client's proof, PKCE), or a caller's option could weaken them.

## Follow-ups

- A tag with this change, and its `docs/compatibility.md` row (no contract change); tresor moves its pin to it.
