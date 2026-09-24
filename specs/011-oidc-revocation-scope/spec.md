# Spec 011: the OIDC core revokes, and refreshes for another scope

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: hugr lab (the tresor session)
- **Consumer side**: tresor specs/012-keychain-sso

## Summary

Two additions to `oidc/`, both for a person's single sign-on (tresor spec 012):
- **`Revoke`** (RFC 7009) and the discovery's `revocation_endpoint`, so a logoff ends a refresh
  token at the IdP, not only in the store;
- **an optional `scope` on `RefreshGrant`** (RFC 6749 §6), so one person's refresh token serves
  another service of the same IdP, in the scope that service asks for.

## Design

- **Discovery.** `Endpoints::revocation_endpoint` is read from the discovery document. Under an
  https issuer, a cleartext one is refused, as the other endpoints are.
- **`Revoke(ep, client_id, client_secret, token, token_type_hint = "refresh_token")`:**
  - it POSTs `token`, `token_type_hint` and `client_id` (and the secret, for a confidential client);
  - `ok` on 200 — RFC 7009 answers 200 for a token the issuer no longer knows, too;
  - a refusal carries the IdP's `error` code and a redacted description;
  - no `revocation_endpoint`: it says so and sends nothing.
- **`RefreshGrant(..., scope = "")`:** `scope` is sent only when given. Nothing changes for existing
  callers.
- **The token never reaches an error:** `Revoke` redacts it, as `RefreshGrant` already does.

## Tests

The fake IdP of `test_oidc_core` gains:
- `revocation_endpoint` and `/revoke` (it records the token, the hint and the client, and refuses
  and quotes one token);
- a record of the refresh grant's scope.

The checks:
- the endpoint is discovered;
- a revocation succeeds as the public client, hinted;
- a refusal carries its code and no token;
- no endpoint: nothing is sent;
- a refresh sends no scope unless given, and the given one when given.

## Compatibility

A module change, not a contract. `RefreshGrant`'s new parameter has a default. It ships in `v0.8.0`
with the keychain module (spec 010).
